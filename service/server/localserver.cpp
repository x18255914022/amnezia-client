#include "localserver.h"

#include <QCoreApplication>
#include <QDebug>
#include <QFileInfo>
#include <QLocalServer>
#include <QLocalSocket>
#include <QObject>
#include <QSharedPointer>
#include <QString>

#include "ipc.h"
#include "killswitch.h"
#include "logger.h"

#ifdef Q_OS_WIN
    #include "tapcontroller_win.h"
#else
    #include <sys/stat.h>
    #include <cstring>  // strerror
    #include <cerrno>
#endif

namespace {
Logger logger("WgDaemonServer");
}

LocalServer::LocalServer(QObject *parent) : QObject(parent),
    m_ipcServer(this)
{
    // Create the server and listen outside of QtRO
    m_server = QSharedPointer<QLocalServer>(new QLocalServer(this));

    if (!m_server->listen(amnezia::getIpcServiceUrl())) {
        qDebug() << QString("Unable to start the server: %1.").arg(m_server->errorString());
        return;
    }

#if !defined(Q_OS_WIN)
    // SECURITY: never expose the privileged service IPC socket with world
    // permissions. The service runs as root; an arbitrary local process that
    // could connect here would be able to drive VPN tunnelling, firewall and
    // routing operations. On Linux the endpoint now lives in the abstract
    // socket namespace (no /tmp file to hijack); on macOS we additionally
    // restrict the socket file to the owner (root).
    const QByteArray socketPath = amnezia::getIpcServicePath().toLocal8Bit();
    if (!socketPath.startsWith('@') &&
        chmod(socketPath.constData(), S_IRUSR | S_IWUSR) < 0) {
        qDebug() << "Failed to restrict permissions on the IPC socket:"
                 << strerror(errno);
    }
#endif

    QObject::connect(m_server.data(), &QLocalServer::newConnection, this, [this]() {
#if !defined(Q_OS_WIN)
        // Verify peer credentials before handing the connection to QtRO.
        while (QLocalSocket *pending = m_server->nextPendingConnection()) {
            if (amnezia::peerCredentialsAllowed(pending->socketDescriptor())) {
                qDebug() << "LocalServer new connection";
                m_serverNode.addHostSideConnection(pending);

                if (!m_isRemotingEnabled) {
                    m_isRemotingEnabled = true;
                    m_serverNode.enableRemoting(&m_ipcServer);
                }
            } else {
                qWarning() << "Rejected IPC connection from unprivileged peer";
                pending->disconnectFromServer();
                pending->deleteLater();
            }
        }
#else
        qDebug() << "LocalServer new connection";
        m_serverNode.addHostSideConnection(m_server->nextPendingConnection());

        if (!m_isRemotingEnabled) {
            m_isRemotingEnabled = true;
            m_serverNode.enableRemoting(&m_ipcServer);
        }
#endif
    });

    // Init Mozilla Wireguard Daemon
    if (!server.initialize()) {
        logger.error() << "Failed to initialize the server";
        return;
    }

    m_networkWatcher.initialize();
    connect(&m_networkWatcher, &NetworkWatcher::networkChanged, &m_ipcServer, &IpcServer::networkChanged);
    connect(&m_networkWatcher, &NetworkWatcher::wakeup, &m_ipcServer, &IpcServer::wakeup);
    KillSwitch::instance()->init();

#ifdef Q_OS_LINUX
    // Signal handling for a proper shutdown.
    QObject::connect(qApp, &QCoreApplication::aboutToQuit,
                     []() { LinuxDaemon::instance()->deactivate(); });
#endif

#ifdef Q_OS_MAC
    // Signal handling for a proper shutdown.
    QObject::connect(qApp, &QCoreApplication::aboutToQuit,
                     []() { MacOSDaemon::instance()->deactivate(); });
#endif

#ifdef Q_OS_WIN
    // Signal handling for a proper shutdown.
    QObject::connect(qApp, &QCoreApplication::aboutToQuit,
                     []() { WindowsDaemon::instance()->deactivate(); });
#endif
}

LocalServer::~LocalServer()
{
    qDebug() << "Local server stopped";
}

