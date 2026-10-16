#ifndef IPC_H
#define IPC_H

#include <QObject>
#include <QString>
#include <QRegularExpression>
#include <QSet>
#include <QStandardPaths>

#include "../client/core/utils/utilities.h"

#define IPC_SERVICE_URL "local:AmneziaVpnIpcInterface"

namespace amnezia {

enum PermittedProcess {
    Invalid,
    OpenVPN,
    Wireguard,
    Tun2Socks,
    CertUtil,
    PermittedProcessCount
};

inline QString permittedProcessPath(PermittedProcess pid)
{
    switch (pid) {
        case PermittedProcess::OpenVPN:
            return Utils::openVpnExecPath();
        case PermittedProcess::Wireguard:
            return Utils::wireguardExecPath();
        case PermittedProcess::CertUtil:
            return Utils::certUtilPath();
        case PermittedProcess::Tun2Socks:
            return Utils::tun2socksPath();
        default:
            return "";
    }
}


// SECURITY: the privileged service used to expose its Qt Remote Objects IPC
// endpoints as plain socket files inside the world-writable /tmp directory.
// Any local process could pre-create or connect to those paths and drive the
// root service (VPN tunnelling, firewall, routing changes). On Linux we now
// use *abstract* namespace sockets (no filesystem entry, cannot be hijacked
// via /tmp races) and additionally verify peer credentials of every incoming
// connection (see amnezia::peerCredentialsAllowed).
inline QString getIpcServicePath() {
#ifdef Q_OS_WIN
    return IPC_SERVICE_URL;
#elif defined(Q_OS_LINUX)
    // Leading '@' selects the abstract socket namespace on Linux.
    return QString("@%1").arg(IPC_SERVICE_URL);
#else
    return QString("%1/AmneziaVpnIpcInterface")
        .arg(QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation));
#endif
}

inline QString getIpcServiceUrl() {
#ifdef Q_OS_WIN
    return IPC_SERVICE_URL;
#else
    return "local:" + getIpcServicePath();
#endif
}

inline QString getIpcProcessPath(int pid) {
#ifdef Q_OS_WIN
    return QString("%1_%2").arg(IPC_SERVICE_URL).arg(pid);
#elif defined(Q_OS_LINUX)
    return QString("@%1_%2").arg(IPC_SERVICE_URL).arg(pid);
#else
    return QString("%1/AmneziaVpnIpcInterface_%2")
        .arg(QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation))
        .arg(pid);
#endif
}

inline QString getIpcProcessUrl(int pid) {
#ifdef Q_OS_WIN
    return QString("%1_%2").arg(IPC_SERVICE_URL).arg(pid);
#else
    return "local:" + getIpcProcessPath(pid);
#endif
}

#if !defined(Q_OS_WIN)
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

// Returns true if the peer of the given AF_UNIX socket is allowed to talk to
// the privileged service. Policy: only root-owned peers are trusted. The
// desktop client reaches the service through a small setuid-root relay, so
// even when started by an unprivileged user its peer euid is 0; any other
// local process connecting directly without privileges is rejected.
inline bool peerCredentialsAllowed(int socketFd)
{
    struct ucred cred;
    socklen_t len = sizeof(cred);
    if (getsockopt(socketFd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
        return false;
    }
    return cred.uid == 0 && cred.gid == 0;
}
#endif

inline QStringList sanitizeArguments(PermittedProcess proc, const QStringList &args) {
    using Validator = std::function<bool(const QString&)>;
    QMap<QString, Validator> namedArgs;
    QList<Validator> positionalArgs;

    switch (proc) {
    case OpenVPN: {
        namedArgs["--config"] = [](const QString& v) { return !v.isEmpty(); };
        namedArgs["--management"] = [](const QString& v) { return !v.isEmpty(); };
        namedArgs["--management-client"] = nullptr;
        positionalArgs.append([](const QString& v) {
            bool ok;
            int port = v.toInt(&ok);
            return ok && port > 0 && port <= 65535;
        });
        break;
    }
    case Tun2Socks:
        namedArgs["-device"] = [](const QString& v) { return v.startsWith("tun://"); };
        namedArgs["-proxy"] = [](const QString& v) { return v.startsWith("socks5://"); };
        break;
    case CertUtil:
        return args;
    default:
        return {};
    }

    QStringList sanitized;

    for (int i = 0, pos = 0; i < args.size(); i++) {
        const auto& key = args[i];

        if (const auto found = namedArgs.find(key); found != namedArgs.end()) {
            const auto validator = found.value();

            if (validator) {
                if (i + 1 < args.size()) {
                    const auto& value = args[i+1];
                    if (validator(value)) {
                        sanitized << key << value;
                        i++;
                    }
                }
            } else {
                sanitized << key;
            }
        } else if (pos < positionalArgs.size()) {
            if (const auto validator = positionalArgs[pos]; validator && validator(key)) {
                sanitized << key;
                pos++;
            }
        }
    }

    return sanitized;
}

} // namespace amnezia

#endif // IPC_H
