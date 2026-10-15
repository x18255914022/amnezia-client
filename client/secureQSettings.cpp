#include "secureQSettings.h"

#include "core/utils/utilities.h"
#include "cryptoUtils.h"
#include <QDataStream>
#include <QDebug>
#include <QDir>
#include <QEventLoop>
#include <QFile>
#include <QIODevice>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QSharedPointer>
#include <QStandardPaths>
#include <QTimer>

#ifdef Q_OS_UNIX
#include <cerrno>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#endif

using namespace QKeychain;

namespace {
    constexpr const char *settingsKeyTag = "settingsKeyTag";
    constexpr const char *settingsIvTag = "settingsIvTag";
    // Local key material fallback for platforms without a system keychain
    // (e.g. Linux desktops without Secret Service / kwallet).
    constexpr const char *keyMaterialFileName = "amnezia_key.bin";
#ifndef CLIENT_KEYCHAIN_NAME_STR
#define CLIENT_KEYCHAIN_NAME_STR "AmneziaVPN-Keychain"
#endif
    constexpr const char *keyChainName = CLIENT_KEYCHAIN_NAME_STR;

    // Load/save 64 bytes of key material (32-byte AES key + 32-byte IV) from a
    // file with 0600 permissions inside the app config directory. Used when the
    // OS keychain is unavailable. Returns an empty QByteArray on any failure.
    QByteArray loadLocalKeyMaterial()
    {
        QFile f(QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation) + "/" + keyMaterialFileName);
        if (!f.exists()) {
            return {};
        }
        if (!f.open(QIODevice::ReadOnly)) {
            qCritical() << "SecureQSettings::loadLocalKeyMaterial cannot open key file:" << f.errorString();
            return {};
        }
        const QByteArray data = f.readAll();
        f.close();
        if (data.size() != 64) {
            qCritical() << "SecureQSettings::loadLocalKeyMaterial corrupted key file size" << data.size();
            return {};
        }
        return data;
    }

    bool storeLocalKeyMaterial(const QByteArray &material)
    {
        if (material.size() != 64) {
            return false;
        }
        const QString dirPath = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
        QDir().mkpath(dirPath);
        const QString filePath = dirPath + "/" + keyMaterialFileName;

        QFile f(filePath);
        if (f.exists()) {
            // Do not overwrite existing key material — that would make previously
            // encrypted settings permanently unreadable.
            return true;
        }
        if (!f.open(QIODevice::WriteOnly | QIODevice::Exclusive)) {
            qCritical() << "SecureQSettings::storeLocalKeyMaterial cannot create key file:" << f.errorString();
            return false;
        }
        f.write(material);
        f.close();
#ifdef Q_OS_UNIX
        if (::chmod(filePath.toUtf8().constData(), S_IRUSR | S_IWUSR) != 0) {
            qWarning() << "SecureQSettings::storeLocalKeyMaterial failed to chmod key file:" << strerror(errno);
        }
#endif
        return true;
    }

#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    // One-shot probe: is the OS keychain (Secret Service / kwallet) usable here?
    bool keychainAvailable()
    {
        static const bool available = []() {
            auto job = QSharedPointer<ReadPasswordJob>(new ReadPasswordJob(keyChainName), &QObject::deleteLater);
            job->setAutoDelete(false);
            job->setKey(QStringLiteral("amneziaProbeKey"));
            QEventLoop loop;
            QObject::connect(job.data(), &ReadPasswordJob::finished, [&loop]() { loop.quit(); });
            QTimer::singleShot(3000, &loop, &QEventLoop::quit);
            job->start();
            loop.exec();
            // The entry normally doesn't exist; we only care whether the backend
            // itself responded without a hard error.
            return !job->error();
        }();
        return available;
    }

    bool canCreateLocalKeyMaterial()
    {
        const QString dirPath = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
        if (!QDir().mkpath(dirPath)) {
            return false;
        }
        QFile f(dirPath + "/.amnezia_write_probe");
        if (!f.open(QIODevice::WriteOnly)) {
            return false;
        }
        f.close();
        f.remove();
        return true;
    }
#endif
}

SecureQSettings::SecureQSettings(const QString &organization, const QString &application, QObject *parent, bool enableEncryption)
    : QObject { parent }, m_settings(organization, application, parent), encryptedKeys({ "Servers/serversList", "Conf/favoriteLocations", "Conf/proxyUrls/agw_state" }), m_encryptionEnabled(enableEncryption)
{
    bool encrypted = m_settings.value("Conf/encrypted").toBool();

    // convert settings to encrypted for if updated to >= 2.1.0
    if (encryptionRequired() && !encrypted) {
        for (const QString &key : m_settings.allKeys()) {
            if (encryptedKeys.contains(key)) {
                const QVariant &val = value(key);
                setValue(key, val);
            }
        }
        m_settings.setValue("Conf/encrypted", true);
    }
}

QVariant SecureQSettings::value(const QString &key, const QVariant &defaultValue) const
{
    QMutexLocker locker(&m_mutex);

    if (m_cache.contains(key)) {
        return m_cache.value(key);
    }

    if (!m_settings.contains(key))
        return defaultValue;

    QVariant retVal;

    // check if value is not encrypted, v. < 2.0.x
    retVal = m_settings.value(key);
    if (retVal.isValid()) {
        if (retVal.userType() == QMetaType::QByteArray && retVal.toByteArray().mid(0, magicString.size()) == magicString) {

            if (getEncKey().isEmpty() || getEncIv().isEmpty()) {
                qCritical() << "SecureQSettings::setValue Decryption requested, but key is empty";
                return {};
            }

            QByteArray encryptedValue = retVal.toByteArray().mid(magicString.size());

            QByteArray decryptedValue = decryptText(encryptedValue);
            QDataStream ds(&decryptedValue, QIODevice::ReadOnly);

            ds >> retVal;

            if (!retVal.isValid()) {
                qWarning() << "SecureQSettings::value settings decryption failed";
                retVal = QVariant();
            }
        }
    } else {
        qWarning() << "SecureQSettings::value invalid QVariant value";
        retVal = QVariant();
    }

    m_cache.insert(key, retVal);
    return retVal;
}

void SecureQSettings::setValue(const QString &key, const QVariant &value)
{
    QMutexLocker locker(&m_mutex);

    if (encryptionRequired() && encryptedKeys.contains(key)) {
        if (!getEncKey().isEmpty() && !getEncIv().isEmpty()) {
            QByteArray decryptedValue;
            {
                QDataStream ds(&decryptedValue, QIODevice::WriteOnly);
                ds << value;
            }

            QByteArray encryptedValue = encryptText(decryptedValue);
            m_settings.setValue(key, magicString + encryptedValue);
        } else {
            qCritical() << "SecureQSettings::setValue Encryption required, but key is empty";
            return;
        }

    } else {
        m_settings.setValue(key, value);
    }

    m_cache.insert(key, value);
}

void SecureQSettings::remove(const QString &key)
{
    QMutexLocker locker(&m_mutex);

    m_settings.remove(key);
    m_cache.remove(key);
}

QByteArray SecureQSettings::backupAppConfig() const
{
    QMutexLocker locker(&m_mutex);

    QJsonObject cfg;

    const auto needToBackup = [this](const QString &key) {
        if (isExcludedFromBackup(key)) {
            return false;
        }
        for (const auto &item : m_fieldsToBackup) {
            if (key.startsWith(item)) {
                return true;
            }
        }
        return false;
    };

    for (const QString &key : m_settings.allKeys()) {

        if (!needToBackup(key))
        {
            continue;
        }

        cfg.insert(key, QJsonValue::fromVariant(value(key)));
    }

    return QJsonDocument(cfg).toJson();
}

bool SecureQSettings::restoreAppConfig(const QByteArray &json)
{
    QMutexLocker locker(&m_mutex);

    QJsonObject cfg = QJsonDocument::fromJson(json).object();
    if (cfg.isEmpty())
        return false;

    for (const QString &key : cfg.keys()) {
        if (isExcludedFromBackup(key)) {
            continue;
        }

        setValue(key, cfg.value(key).toVariant());
    }

    return true;
}

bool SecureQSettings::isExcludedFromBackup(const QString &key) const
{
    for (const auto &item : m_fieldsExcludedFromBackup) {
        if (key.startsWith(item)) {
            return true;
        }
    }
    return false;
}

void SecureQSettings::clearSettings()
{
    QMutexLocker locker(&m_mutex);
    m_settings.clear();
    m_cache.clear();
}

QByteArray SecureQSettings::encryptText(const QByteArray &value) const
{
    // Authenticated encryption (AES-256-CBC + HMAC-SHA256, encrypt-then-MAC):
    // protects settings values from undetected tampering / padding-oracle attacks.
    QByteArray result = CryptoUtils::encryptAes256CbcHmac(value, getEncKey(), getEncIv());
    if (result.isEmpty() && !value.isEmpty()) {
        qCritical() << "error when encrypting the settings value";
    }
    return result;
}

QByteArray SecureQSettings::decryptText(const QByteArray &ba) const
{
    // Accepts both new authenticated blobs and legacy unauthenticated ones
    // (transparently handled inside decryptAes256CbcHmac).
    QByteArray result = CryptoUtils::decryptAes256CbcHmac(ba, getEncKey(), getEncIv());
    if (result.isEmpty() && !ba.isEmpty()) {
        qCritical() << "error when decrypting the settings value";
    }
    return result;
}

bool SecureQSettings::encryptionRequired() const
{
    if (!m_encryptionEnabled) {
        return false;
    }
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    // QtKeyChain may be unavailable on Linux (no Secret Service / kwallet).
    // Encryption is still required: getEncKey()/getEncIv() fall back to a
    // local 0600 key-material file when the OS keychain cannot store the keys.
    // Only disable encryption if that fallback is also unusable.
    if (!keychainAvailable() && loadLocalKeyMaterial().isEmpty() && !canCreateLocalKeyMaterial()) {
        qCritical() << "SecureQSettings::encryptionRequired no secure key storage available, "
                       "settings will be stored unencrypted";
        return false;
    }
#endif
    return true;
}

QByteArray SecureQSettings::getEncKey() const
{
    if (!m_key.isEmpty()) {
        return m_key;
    }

#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    // On Linux prefer the local key-material file: it is deterministic and does
    // not depend on a D-Bus keychain daemon that may be missing or broken.
    const QByteArray localMaterial = loadLocalKeyMaterial();
    if (!localMaterial.isEmpty()) {
        m_key = localMaterial.left(32);
        if (m_iv.isEmpty()) {
            m_iv = localMaterial.mid(32);
        }
        return m_key;
    }
#endif

    // load keys from system key storage
    m_key = getSecTag(settingsKeyTag);

    if (m_key.isEmpty()) {
        // Create new key
        QByteArray key = CryptoUtils::generateRandomBytes(32);
        if (key.isEmpty()) {
            qCritical() << "SecureQSettings::getEncKey Unable to generate new enc key";
            return {};
        }

        setSecTag(settingsKeyTag, key);

        // check
        m_key = getSecTag(settingsKeyTag);
        if (key != m_key) {
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
            // Keychain is not usable — fall back to the local 0600 key file.
            // Generate IV together with the key so both land in one material blob.
            QByteArray iv = CryptoUtils::generateRandomBytes(32);
            if (iv.isEmpty() || !storeLocalKeyMaterial(key + iv)) {
                qCritical() << "SecureQSettings::getEncKey Unable to store key: neither keychain nor local file available";
                return {};
            }
            m_key = key;
            m_iv = iv;
            return m_key;
#else
            qCritical() << "SecureQSettings::getEncKey Unable to store key in keychain" << key.size() << m_key.size();
            return {};
#endif
        }
    }

    return m_key;
}

QByteArray SecureQSettings::getEncIv() const
{
    if (!m_iv.isEmpty()) {
        return m_iv;
    }

#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    const QByteArray localMaterial = loadLocalKeyMaterial();
    if (!localMaterial.isEmpty()) {
        m_iv = localMaterial.mid(32);
        if (m_key.isEmpty()) {
            m_key = localMaterial.left(32);
        }
        return m_iv;
    }
#endif

    // load keys from system key storage
    m_iv = getSecTag(settingsIvTag);

    if (m_iv.isEmpty()) {
        // Create new IV
        QByteArray iv = CryptoUtils::generateRandomBytes(32);
        if (iv.isEmpty()) {
            qCritical() << "SecureQSettings::getEncIv Unable to generate new enc IV";
            return {};
        }
        setSecTag(settingsIvTag, iv);

        // check
        m_iv = getSecTag(settingsIvTag);
        if (iv != m_iv) {
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
            // Keychain unusable — persist IV (together with the key, if known)
            // in the local 0600 key-material file.
            QByteArray key = m_key;
            if (key.isEmpty()) {
                key = getSecTag(settingsKeyTag);
                if (key.isEmpty()) {
                    key = CryptoUtils::generateRandomBytes(32);
                }
            }
            if (key.size() == 32 && storeLocalKeyMaterial(key + iv)) {
                m_key = key;
                m_iv = iv;
                return m_iv;
            }
#endif
            qCritical() << "SecureQSettings::getEncIv Unable to store IV in keychain" << iv.size() << m_iv.size();
            return {};
        }
    }

    return m_iv;
}

QByteArray SecureQSettings::getSecTag(const QString &tag)
{
    auto job = QSharedPointer<ReadPasswordJob>(new ReadPasswordJob(keyChainName), &QObject::deleteLater);
    job->setAutoDelete(false);
    job->setKey(tag);
    QEventLoop loop;
    job->connect(job.data(), &ReadPasswordJob::finished, job.data(), [&loop]() { loop.quit(); });
    job->start();
    loop.exec();

    if (job->error()) {
        qCritical() << "SecureQSettings::getSecTag Error:" << job->errorString();
    }

    return job->binaryData();
}

void SecureQSettings::setSecTag(const QString &tag, const QByteArray &data)
{
    auto job = QSharedPointer<WritePasswordJob>(new WritePasswordJob(keyChainName), &QObject::deleteLater);
    job->setAutoDelete(false);
    job->setKey(tag);
    job->setBinaryData(data);
    QEventLoop loop;
    QTimer::singleShot(1000, &loop, SLOT(quit()));
    job->connect(job.data(), &WritePasswordJob::finished, job.data(), [&loop]() { loop.quit(); });
    job->start();
    loop.exec();

    if (job->error()) {
        qCritical() << "SecureQSettings::setSecTag Error:" << job->errorString();
    }
}
