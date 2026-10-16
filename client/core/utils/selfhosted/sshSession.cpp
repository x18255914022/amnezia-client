#include "sshSession.h"
#include <algorithm>

#include <QCryptographicHash>
#include <QDir>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLoggingCategory>
#include <QPointer>
#include <QRegularExpression>
#include <QTemporaryFile>
#include <QThread>
#include <QTimer>
#include <QtConcurrent>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sys/stat.h>

#include <chrono>
#include <thread>

#include "core/utils/containerEnum.h"
#include "core/utils/containers/containerUtils.h"
#include "core/utils/protocolEnum.h"
#include "core/utils/networkUtilities.h"
#include "core/utils/selfhosted/scriptsRegistry.h"
#include "logger.h"
#include "core/utils/utilities.h"

namespace
{
    Logger logger("SshSession");
}

SshSession::SshSession(QObject *parent) : QObject(parent)
{
}

SshSession::~SshSession()
{
    m_sshClient.disconnectFromHost();
}

ErrorCode SshSession::runScript(const ServerCredentials &credentials, QString script,
                                const std::function<ErrorCode(const QString &, libssh::Client &)> &cbReadStdOut,
                                const std::function<ErrorCode(const QString &, libssh::Client &)> &cbReadStdErr)
{

    auto error = m_sshClient.connectToHost(credentials);
    if (error != ErrorCode::NoError) {
        return error;
    }

    script.replace("\r", "");

    qDebug() << "SshSession::Run script";

    QString totalLine;
    const QStringList &lines = script.split("\n", Qt::SkipEmptyParts);
    for (int i = 0; i < lines.count(); i++) {
        QString currentLine = lines.at(i);

        if (totalLine.isEmpty()) {
            totalLine = currentLine;
        } else {
            totalLine = totalLine + "\n" + currentLine;
        }

        QString lineToExec;
        if (currentLine.endsWith("\\")) {
            continue;
        } else {
            lineToExec = totalLine;
            totalLine.clear();
        }

        if (lineToExec.startsWith("#")) {
            continue;
        }

        // Security: remote install scripts may embed secrets (private keys,
        // passwords, MTProxy secrets after variable substitution). Never write
        // raw command lines to the log; only a debug build with an explicitly
        // defined QDEBUG_VERBOSE_LOG_ENABLED macro may do so.
#ifdef QDEBUG_VERBOSE_LOG_ENABLED
        qDebug().noquote() << lineToExec;
#endif

        error = m_sshClient.executeCommand(lineToExec, cbReadStdOut, cbReadStdErr);
        if (error != ErrorCode::NoError) {
            return error;
        }
    }

    qDebug().noquote() << "SshSession::runScript finished\n";
    return ErrorCode::NoError;
}

ErrorCode SshSession::runContainerScript(const ServerCredentials &credentials, DockerContainer container, QString script,
                                         const std::function<ErrorCode(const QString &, libssh::Client &)> &cbReadStdOut,
                                         const std::function<ErrorCode(const QString &, libssh::Client &)> &cbReadStdErr)
{
    QString fileName = "/opt/amnezia/" + Utils::getRandomString(16) + ".sh";

    ErrorCode e = uploadTextFileToContainer(container, credentials, script, fileName);
    if (e)
        return e;

    const bool useSh = container == DockerContainer::Socks5Proxy || container == DockerContainer::MtProxy
            || container == DockerContainer::Telemt || container == DockerContainer::TProxy;
    QString runner = QString("sudo docker exec -i $CONTAINER_NAME %2 %1 ").arg(fileName, useSh ? "sh" : "bash");
    e = runScript(credentials, replaceVars(runner, amnezia::genBaseVars(credentials, container, QString(), QString())), cbReadStdOut, cbReadStdErr);

    QString remover = QString("sudo docker exec -i $CONTAINER_NAME rm %1 ").arg(fileName);
    runScript(credentials, replaceVars(remover, amnezia::genBaseVars(credentials, container, QString(), QString())), cbReadStdOut, cbReadStdErr);

    return e;
}

ErrorCode SshSession::uploadTextFileToContainer(DockerContainer container, const ServerCredentials &credentials, const QString &file,
                                                const QString &path, libssh::ScpOverwriteMode overwriteMode)
{
    ErrorCode e = ErrorCode::NoError;

    // The destination path is interpolated into remote shell commands below.
    // Reject anything that could break out of those commands (injection
    // defense in depth); legitimate paths are plain absolute POSIX paths.
    auto isValidRemotePath = [](const QString &p) {
        if (p.isEmpty() || !p.startsWith(QLatin1Char('/'))) {
            return false;
        }
        static const QRegularExpression re(QStringLiteral("^/[A-Za-z0-9_.:/-]+$"));
        if (!re.match(p).hasMatch()) {
            return false;
        }
        if (p.contains(QStringLiteral(".."))) {
            return false;
        }
        return true;
    };
    if (!isValidRemotePath(path)) {
        return ErrorCode::InternalError;
    }

    QString tmpFileName = QString("/tmp/%1.tmp").arg(Utils::getRandomString(16));
    e = uploadFileToHost(credentials, file.toUtf8(), tmpFileName);
    if (e)
        return e;

    QString stdOut;
    auto cbReadStd = [&](const QString &data, libssh::Client &) {
        stdOut += data + "\n";
        return ErrorCode::NoError;
    };

    // mkdir
    QString mkdir = QString("sudo docker exec -i $CONTAINER_NAME mkdir -p  \"$(dirname %1)\"").arg(path);

    e = runScript(credentials, replaceVars(mkdir, amnezia::genBaseVars(credentials, container, QString(), QString())));
    if (e)
        return e;

    if (overwriteMode == libssh::ScpOverwriteMode::ScpOverwriteExisting) {
        e = runScript(credentials,
                      replaceVars(QStringLiteral("sudo docker cp %1 $CONTAINER_NAME:/%2").arg(tmpFileName, path),
                                  amnezia::genBaseVars(credentials, container, QString(), QString())),
                      cbReadStd, cbReadStd);

        if (e)
            return e;
    } else if (overwriteMode == libssh::ScpOverwriteMode::ScpAppendToExisting) {
        e = runScript(credentials,
                      replaceVars(QStringLiteral("sudo docker cp %1 $CONTAINER_NAME:/%2").arg(tmpFileName, tmpFileName),
                                  amnezia::genBaseVars(credentials, container, QString(), QString())),
                      cbReadStd, cbReadStd);

        if (e)
            return e;

        e = runScript(credentials,
                      replaceVars(QStringLiteral("sudo docker exec -i $CONTAINER_NAME sh -c \"cat %1 >> %2\"").arg(tmpFileName, path),
                                  amnezia::genBaseVars(credentials, container, QString(), QString())),
                      cbReadStd, cbReadStd);

        if (e)
            return e;
    } else
        return ErrorCode::NotImplementedError;

    if (stdOut.contains("Error") && stdOut.contains("No such container")) {
        return ErrorCode::ServerContainerMissingError;
    }

    runScript(credentials, replaceVars(QString("sudo shred -u %1").arg(tmpFileName), amnezia::genBaseVars(credentials, container, QString(), QString())));
    return e;
}

QByteArray SshSession::getTextFileFromContainer(DockerContainer container, const ServerCredentials &credentials, const QString &path,
                                                ErrorCode &errorCode)
{

    errorCode = ErrorCode::NoError;

    QString script = QStringLiteral("sudo docker exec -i %1 sh -c \"xxd -p '%2' 2>/dev/null || od -An -v -tx1 '%2'\"")
                             .arg(ContainerUtils::containerToString(container), path);

    QString stdOut;
    auto cbReadStdOut = [&](const QString &data, libssh::Client &) {
        stdOut += data;
        return ErrorCode::NoError;
    };

    errorCode = runScript(credentials, script, cbReadStdOut);
    return QByteArray::fromHex(stdOut.toUtf8());
}

ErrorCode SshSession::uploadFileToHost(const ServerCredentials &credentials, const QByteArray &data, const QString &remotePath,
                                       libssh::ScpOverwriteMode overwriteMode)
{
    auto error = m_sshClient.connectToHost(credentials);
    if (error != ErrorCode::NoError) {
        return error;
    }

    QTemporaryFile localFile;
    localFile.open();
    localFile.write(data);
    localFile.close();

    error = m_sshClient.scpFileCopy(overwriteMode, localFile.fileName(), remotePath, "non_desc");

    if (error != ErrorCode::NoError) {
        return error;
    }
    return ErrorCode::NoError;
}

QString SshSession::checkSshConnection(const ServerCredentials &credentials, ErrorCode &errorCode)
{
    QString stdOut;
    auto cbReadStdOut = [&](const QString &data, libssh::Client &) {
        stdOut += data + "\n";
        return ErrorCode::NoError;
    };
    auto cbReadStdErr = [&](const QString &data, libssh::Client &) {
        stdOut += data + "\n";
        return ErrorCode::NoError;
    };

    errorCode = runScript(credentials, amnezia::scriptData(SharedScriptType::check_connection), cbReadStdOut, cbReadStdErr);

    return stdOut;
}

QString SshSession::replaceVars(const QString &script, const Vars &vars)
{
    // Safe variable substitution for remote shell scripts.
    //
    // Previous implementation did a plain substring replace, which allowed an
    // injection of the form `$X${Y}` + var X = "foo$(cmd)" to re-expand into
    // executable shell code during a later pass (template-injection /
    // re-substitution).  This version performs a single left-to-right scan:
    // each placeholder is matched against the known variable names (longest
    // first), and the substituted value is never rescanned.  Text that looks
    // like a placeholder but isn't one is emitted verbatim.
    if (vars.isEmpty()) {
        return script;
    }

    // Sort keys by descending length so $CONTAINER_NAME beats $CONTAINER etc.
    QVector<QPair<QString, QString>> ordered;
    ordered.reserve(vars.size());
    for (const auto &var : vars) {
        if (var.first.isEmpty()) {
            continue;
        }
        ordered.append(var);
    }
    std::sort(ordered.begin(), ordered.end(),
              [](const QPair<QString, QString> &a, const QPair<QString, QString> &b) {
                  return a.first.size() > b.first.size();
              });

    QString result;
    result.reserve(script.size());

    int i = 0;
    while (i < script.size()) {
        bool replaced = false;
        if (script.at(i) == QLatin1Char('$')) {
            for (const auto &var : ordered) {
                if (script.compare(i, var.first.size(), var.first, Qt::CaseSensitive) == 0) {
                    result += var.second;
                    i += var.first.size();
                    replaced = true;
                    break;
                }
            }
        }
        if (!replaced) {
            result += script.at(i);
            ++i;
        }
    }

    return result;
}

ErrorCode SshSession::getDecryptedPrivateKey(const ServerCredentials &credentials, QString &decryptedPrivateKey,
                                             const std::function<QString()> &callback)
{
    auto error = m_sshClient.getDecryptedPrivateKey(credentials, decryptedPrivateKey, callback);
    return error;
}
