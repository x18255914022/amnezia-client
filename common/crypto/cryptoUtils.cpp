#include "cryptoUtils.h"

#include <openssl/hmac.h>
#include <openssl/sha.h>

namespace
{
    constexpr int kAesKeySize = 32;   // AES-256
    constexpr int kAesIvSize = 16;    // CBC block size
    constexpr int kAesBlockSize = 16;
    constexpr int kHmacKeySize = 32;
    constexpr int kHmacTagSize = SHA256_DIGEST_LENGTH;  // 32 bytes
    constexpr char kMacedMagic = 'M';                   // version tag for encrypt-then-MAC blobs

    QByteArray lastOpenSslError()
    {
        return QByteArray(ERR_error_string(ERR_get_error(), nullptr));
    }

    // Derive an independent MAC key from the encryption key via domain-separated SHA-256.
    QByteArray deriveMacKey(const QByteArray &encKey)
    {
        static const char kDomain[] = "amnezia-settings-mac-v1";
        QByteArray input;
        input.append(kDomain, sizeof(kDomain) - 1);
        input.append(encKey);
        return QCryptographicHash::hash(input, QCryptographicHash::Sha256);
    }

    QByteArray computeHmac(const QByteArray &key, const QByteArray &data)
    {
        unsigned char out[EVP_MAX_MD_SIZE];
        unsigned int outLen = 0;
        if (HMAC(EVP_sha256(), key.constData(), key.size(),
                 reinterpret_cast<const unsigned char *>(data.constData()), static_cast<size_t>(data.size()),
                 out, &outLen) == nullptr) {
            qCritical() << "CryptoUtils HMAC failed:" << lastOpenSslError();
            return {};
        }
        return QByteArray(reinterpret_cast<const char *>(out), static_cast<int>(outLen));
    }

    // Constant-time comparison to avoid timing side channels on MAC tags.
    bool constTimeEqual(const QByteArray &a, const QByteArray &b)
    {
        if (a.size() != b.size()) {
            return false;
        }
        volatile unsigned char diff = 0;
        for (int i = 0; i < a.size(); ++i) {
            diff |= static_cast<unsigned char>(a.at(i)) ^ static_cast<unsigned char>(b.at(i));
        }
        return diff == 0;
    }

    // Raw AES-256-CBC core shared by the plain and authenticated variants.
    QByteArray aesCbcEncrypt(const QByteArray &data, const QByteArray &key, const QByteArray &iv)
    {
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx { EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free };
        if (!ctx) {
            qCritical() << "aesCbcEncrypt EVP_CIPHER_CTX_new failed:" << lastOpenSslError();
            return {};
        }

        if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char *>(key.constData()),
                               reinterpret_cast<const unsigned char *>(iv.constData()))
            != 1) {
            qCritical() << "aesCbcEncrypt EVP_EncryptInit_ex failed:" << lastOpenSslError();
            return {};
        }

        QByteArray cipherText(data.size() + kAesBlockSize, Qt::Uninitialized);
        int length = 0;
        int cipherTextLength = 0;

        if (EVP_EncryptUpdate(ctx.get(), reinterpret_cast<unsigned char *>(cipherText.data()), &length,
                              reinterpret_cast<const unsigned char *>(data.constData()), data.size())
            != 1) {
            qCritical() << "aesCbcEncrypt EVP_EncryptUpdate failed:" << lastOpenSslError();
            return {};
        }
        cipherTextLength = length;

        if (EVP_EncryptFinal_ex(ctx.get(), reinterpret_cast<unsigned char *>(cipherText.data()) + cipherTextLength, &length) != 1) {
            qCritical() << "aesCbcEncrypt EVP_EncryptFinal_ex failed:" << lastOpenSslError();
            return {};
        }
        cipherTextLength += length;

        cipherText.resize(cipherTextLength);
        return cipherText;
    }

    QByteArray aesCbcDecrypt(const QByteArray &data, const QByteArray &key, const QByteArray &iv)
    {
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx { EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free };
        if (!ctx) {
            qCritical() << "aesCbcDecrypt EVP_CIPHER_CTX_new failed:" << lastOpenSslError();
            return {};
        }

        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char *>(key.constData()),
                               reinterpret_cast<const unsigned char *>(iv.constData()))
            != 1) {
            qCritical() << "aesCbcDecrypt EVP_DecryptInit_ex failed:" << lastOpenSslError();
            return {};
        }

        QByteArray plainText(data.size() + kAesBlockSize, Qt::Uninitialized);
        int length = 0;
        int plainTextLength = 0;

        if (EVP_DecryptUpdate(ctx.get(), reinterpret_cast<unsigned char *>(plainText.data()), &length,
                              reinterpret_cast<const unsigned char *>(data.constData()), data.size())
            != 1) {
            qCritical() << "aesCbcDecrypt EVP_DecryptUpdate failed:" << lastOpenSslError();
            return {};
        }
        plainTextLength = length;

        if (EVP_DecryptFinal_ex(ctx.get(), reinterpret_cast<unsigned char *>(plainText.data()) + plainTextLength, &length) != 1) {
            qCritical() << "aesCbcDecrypt EVP_DecryptFinal_ex failed:" << lastOpenSslError();
            return {};
        }
        plainTextLength += length;

        plainText.resize(plainTextLength);
        return plainText;
    }
}

QByteArray CryptoUtils::generateRandomBytes(int size)
{
    if (size <= 0) {
        qCritical() << "CryptoUtils::generateRandomBytes invalid size" << size;
        return {};
    }

    QByteArray buffer(size, Qt::Uninitialized);
    if (RAND_bytes(reinterpret_cast<unsigned char *>(buffer.data()), size) != 1) {
        qCritical() << "CryptoUtils::generateRandomBytes RAND_bytes failed:" << lastOpenSslError();
        return {};
    }

    return buffer;
}

QByteArray CryptoUtils::encryptAes256Cbc(const QByteArray &data, const QByteArray &key, const QByteArray &iv)
{
    if (key.size() != kAesKeySize || iv.size() < kAesIvSize) {
        qCritical() << "CryptoUtils::encryptAes256Cbc invalid key/iv size" << key.size() << iv.size();
        return {};
    }

    // Legacy behaviour: first 16 bytes of the IV buffer are used.
    return aesCbcEncrypt(data, key, iv.left(kAesIvSize));
}

QByteArray CryptoUtils::decryptAes256Cbc(const QByteArray &data, const QByteArray &key, const QByteArray &iv)
{
    if (key.size() != kAesKeySize || iv.size() < kAesIvSize) {
        qCritical() << "CryptoUtils::decryptAes256Cbc invalid key/iv size" << key.size() << iv.size();
        return {};
    }

    return aesCbcDecrypt(data, key, iv.left(kAesIvSize));
}

QByteArray CryptoUtils::encryptAes256CbcHmac(const QByteArray &data, const QByteArray &key, const QByteArray &iv)
{
    if (key.size() != kAesKeySize || iv.size() < kAesIvSize) {
        qCritical() << "CryptoUtils::encryptAes256CbcHmac invalid key/iv size" << key.size() << iv.size();
        return {};
    }

    const QByteArray realIv = iv.left(kAesIvSize);
    const QByteArray cipherText = aesCbcEncrypt(data, key, realIv);
    if (cipherText.isEmpty()) {
        qCritical() << "CryptoUtils::encryptAes256CbcHmac encryption failed";
        return {};
    }

    // Encrypt-then-MAC: tag covers IV || ciphertext so both are authenticated.
    QByteArray macInput;
    macInput.reserve(realIv.size() + cipherText.size());
    macInput.append(realIv);
    macInput.append(cipherText);

    const QByteArray tag = computeHmac(deriveMacKey(key), macInput);
    if (tag.size() != kHmacTagSize) {
        return {};
    }

    QByteArray blob;
    blob.reserve(1 + realIv.size() + tag.size() + cipherText.size());
    blob.append(kMacedMagic);
    blob.append(realIv);
    blob.append(tag);
    blob.append(cipherText);
    return blob;
}

QByteArray CryptoUtils::decryptAes256CbcHmac(const QByteArray &data, const QByteArray &key, const QByteArray &iv)
{
    if (key.size() != kAesKeySize || iv.size() < kAesIvSize) {
        qCritical() << "CryptoUtils::decryptAes256CbcHmac invalid key/iv size" << key.size() << iv.size();
        return {};
    }

    // Backward compatibility: legacy blobs written before encrypt-then-MAC were
    // introduced have no leading 'M' tag and start directly with the ciphertext.
    if (data.isEmpty() || data.at(0) != kMacedMagic) {
        return aesCbcDecrypt(data, key, iv.left(kAesIvSize));
    }

    constexpr int headerSize = 1 + kAesIvSize + kHmacTagSize;
    if (data.size() < headerSize) {
        qCritical() << "CryptoUtils::decryptAes256CbcHmac truncated authenticated blob";
        return {};
    }

    const QByteArray storedIv = data.mid(1, kAesIvSize);
    const QByteArray storedTag = data.mid(1 + kAesIvSize, kHmacTagSize);
    const QByteArray cipherText = data.mid(headerSize);

    QByteArray macInput;
    macInput.reserve(storedIv.size() + cipherText.size());
    macInput.append(storedIv);
    macInput.append(cipherText);

    const QByteArray expectedTag = computeHmac(deriveMacKey(key), macInput);
    if (expectedTag.isEmpty() || !constTimeEqual(expectedTag, storedTag)) {
        qCritical() << "CryptoUtils::decryptAes256CbcHmac authentication tag mismatch — data tampered or wrong key";
        return {};
    }

    return aesCbcDecrypt(cipherText, key, storedIv);
}

EVP_PKEY *CryptoUtils::loadPublicKeyFromPem(const QByteArray &pem)
{
    std::unique_ptr<BIO, decltype(&BIO_free)> bio { BIO_new_mem_buf(pem.constData(), pem.size()), BIO_free };
    if (!bio) {
        qCritical() << "CryptoUtils::loadPublicKeyFromPem BIO_new_mem_buf failed:" << lastOpenSslError();
        return nullptr;
    }

    EVP_PKEY *key = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    if (!key) {
        qCritical() << "CryptoUtils::loadPublicKeyFromPem PEM_read_bio_PUBKEY failed:" << lastOpenSslError();
        return nullptr;
    }

    return key;
}

QByteArray CryptoUtils::rsaEncrypt(const QByteArray &data, EVP_PKEY *publicKey, int padding)
{
    if (!publicKey) {
        qCritical() << "CryptoUtils::rsaEncrypt public key is null";
        return {};
    }

    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx { EVP_PKEY_CTX_new(publicKey, nullptr), EVP_PKEY_CTX_free };
    if (!ctx) {
        qCritical() << "CryptoUtils::rsaEncrypt EVP_PKEY_CTX_new failed:" << lastOpenSslError();
        return {};
    }

    if (EVP_PKEY_encrypt_init(ctx.get()) != 1) {
        qCritical() << "CryptoUtils::rsaEncrypt EVP_PKEY_encrypt_init failed:" << lastOpenSslError();
        return {};
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), padding) != 1) {
        qCritical() << "CryptoUtils::rsaEncrypt EVP_PKEY_CTX_set_rsa_padding failed:" << lastOpenSslError();
        return {};
    }

    const auto *plainData = reinterpret_cast<const unsigned char *>(data.constData());

    std::size_t cipherTextLength = 0;
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &cipherTextLength, plainData, data.size()) != 1) {
        qCritical() << "CryptoUtils::rsaEncrypt couldn't determine buffer length:" << lastOpenSslError();
        return {};
    }

    QByteArray cipherText(static_cast<int>(cipherTextLength), Qt::Uninitialized);
    if (EVP_PKEY_encrypt(ctx.get(), reinterpret_cast<unsigned char *>(cipherText.data()), &cipherTextLength, plainData, data.size())
        != 1) {
        qCritical() << "CryptoUtils::rsaEncrypt EVP_PKEY_encrypt failed:" << lastOpenSslError();
        return {};
    }

    cipherText.resize(static_cast<int>(cipherTextLength));
    return cipherText;
}
