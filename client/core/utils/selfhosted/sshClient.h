#ifndef SSHCLIENT_H
#define SSHCLIENT_H

#include <QObject>
#include <QFile>
#include <QHash>

#include <fcntl.h>
#include <memory>

#include <libssh/libssh.h>
#include <libssh/kex.h>
#include <libssh/session.h>

#include "core/utils/errorCodes.h"
#include "core/utils/routeModes.h"
#include "core/utils/commonStructs.h"

using namespace amnezia;

namespace libssh {
    enum ScpOverwriteMode {
        /*! Overwrite any existing files */
        ScpOverwriteExisting = O_TRUNC,
        /*! Append new content if the file already exists */
        ScpAppendToExisting = O_APPEND
    };
    class Client : public QObject
    {
        Q_OBJECT
    public:
        Client() = default;
        ~Client() = default;

        ErrorCode connectToHost(const ServerCredentials &credentials);
        void disconnectFromHost();
        ErrorCode executeCommand(const QString &data,
                                 const std::function<ErrorCode (const QString &, Client &)> &cbReadStdOut,
                                 const std::function<ErrorCode (const QString &, Client &)> &cbReadStdErr);
        ErrorCode writeResponse(const QString &data);
        ErrorCode scpFileCopy(const ScpOverwriteMode overwriteMode,
                               const QString &localPath,
                               const QString &remotePath,
                               const QString &fileDesc);
        ErrorCode getDecryptedPrivateKey(const ServerCredentials &credentials, QString &decryptedPrivateKey, const std::function<QString()> &passphraseCallback);
    private:
        ErrorCode closeChannel();
        void closeScpSession();
        ErrorCode fromLibsshErrorCode();
        ErrorCode fromFileErrorCode(QFileDevice::FileError fileError);
        // Trust-on-first-use verification of the server host key against the
        // app's own known hosts store. Returns NoError only when the key is
        // newly pinned or matches the previously pinned one.
        ErrorCode verifyAndPinHostKey(const std::string &host, int port);
        static int callback(const char *prompt, char *buf, size_t len, int echo, int verify, void *userdata);

        ssh_session m_session = nullptr;
        ssh_channel m_channel = nullptr;
        ssh_scp m_scpSession = nullptr;

        // Pinned SHA256 fingerprints of server host keys ("host:port" -> hex).
        QHash<QString, QByteArray> m_pinnedHostKeys;

        static std::function<QString()> m_passphraseCallback;
    signals:
        void writeToChannelFinished();
        void scpFileCopyFinished();
    };
}

#endif // SSHCLIENT_H
