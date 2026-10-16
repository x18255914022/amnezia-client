#include "ipcserver.h"

#include <QDateTime>
#include <QDebug>
#include <QFileInfo>
#include <QHostAddress>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QObject>
#include <QRemoteObjectHost>
#include <QRemoteObjectNode>
#include <QString>
#include <QStringList>

#if !defined(Q_OS_WIN)
#  include <sys/stat.h>
#  include <cstring>
#  include <cerrno>
#endif

#include "logger.h"
#include "router.h"
#include "killswitch.h"
#include "xray.h"

#ifdef Q_OS_WIN
    #include "tapcontroller_win.h"
#endif


IpcServer::IpcServer(QObject *parent) : IpcInterfaceSource(parent)
{
    connect(&m_pingHelper, &PingHelper::connectionLose, this, &IpcServer::connectionLose);
}

int IpcServer::createPrivilegedProcess()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::createPrivilegedProcess";
#endif

    m_localpid++;

    ProcessDescriptor pd(this);

    if (!pd.localServer->listen(amnezia::getIpcProcessUrl(m_localpid))) {
        qDebug() << QString("Unable to start the server: %1.").arg(pd.localServer->errorString());
        return -1;
    }

#if !defined(Q_OS_WIN)
    // SECURITY: same policy as the main service endpoint - no world-writable
    // socket files; per-process endpoints live in the abstract namespace on
    // Linux and are chmod'ed to 0600 on macOS.
    const QByteArray procPath = amnezia::getIpcProcessPath(m_localpid).toLocal8Bit();
    if (!procPath.startsWith('@') &&
        chmod(procPath.constData(), S_IRUSR | S_IWUSR) < 0) {
        qDebug() << "Failed to restrict permissions on the IPC process socket:"
                 << strerror(errno);
    }
#endif

    // Make sure any connections are handed to QtRO
    QObject::connect(pd.localServer.data(), &QLocalServer::newConnection, this, [pd]() {
#if !defined(Q_OS_WIN)
        while (QLocalSocket *pending = pd.localServer->nextPendingConnection()) {
            if (!amnezia::peerCredentialsAllowed(pending->socketDescriptor())) {
                qWarning() << "Rejected privileged-process IPC connection from unprivileged peer";
                pending->disconnectFromServer();
                pending->deleteLater();
                continue;
            }
            qDebug() << "IpcServer new connection";
            if (pd.serverNode) {
                pd.serverNode->addHostSideConnection(pending);
                pd.serverNode->enableRemoting(pd.ipcProcess.data());
            }
        }
#else
        qDebug() << "IpcServer new connection";
        if (pd.serverNode) {
            pd.serverNode->addHostSideConnection(pd.localServer->nextPendingConnection());
            pd.serverNode->enableRemoting(pd.ipcProcess.data());
        }
#endif
    });

    QObject::connect(pd.serverNode.data(), &QRemoteObjectHost::error, this,
                     [pd](QRemoteObjectNode::ErrorCode errorCode) { qDebug() << "QRemoteObjectHost::error" << errorCode; });

    QObject::connect(pd.serverNode.data(), &QRemoteObjectHost::destroyed, this, [pd]() { qDebug() << "QRemoteObjectHost::destroyed"; });

    m_processes.insert(m_localpid, pd);

    return m_localpid;
}

int IpcServer::routeAddList(const QString &gw, const QStringList &ips)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::routeAddList";
#endif

    return Router::routeAddList(gw, ips);
}

bool IpcServer::clearSavedRoutes()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::clearSavedRoutes";
#endif

    return Router::clearSavedRoutes();
}

bool IpcServer::routeDeleteList(const QString &gw, const QStringList &ips)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::routeDeleteList";
#endif

    return Router::routeDeleteList(gw, ips);
}

bool IpcServer::flushDns()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::flushDns";
#endif

    return Router::flushDns();
}

void IpcServer::resetIpStack()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::resetIpStack";
#endif

    Router::resetIpStack();
}

bool IpcServer::checkAndInstallDriver()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::checkAndInstallDriver";
#endif

#ifdef Q_OS_WIN
    return TapController::checkAndSetup();
#else
    return true;
#endif
}

QStringList IpcServer::getTapList()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::getTapList";
#endif

#ifdef Q_OS_WIN
    return TapController::getTapList();
#else
    return QStringList();
#endif
}

void IpcServer::cleanUp()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::cleanUp";
#endif

    Logger::deInit();
    Logger::cleanUp();
}

void IpcServer::clearLogs()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::clearLogs";
#endif

    Logger::clearLogs(true);
}

bool IpcServer::createTun(const QString &dev, const QString &subnet)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::createTun";
#endif

    return Router::createTun(dev, subnet);
}

bool IpcServer::deleteTun(const QString &dev)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::deleteTun";
#endif

    return Router::deleteTun(dev);
}

bool IpcServer::updateResolvers(const QString &ifname, const QList<QHostAddress> &resolvers)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::updateResolvers";
#endif

    return Router::updateResolvers(ifname, resolvers);
}

bool IpcServer::restoreResolvers()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::restoreResolvers";
#endif

    return Router::restoreResolvers();
}

bool IpcServer::StartRoutingIpv6()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::StartRoutingIpv6";
#endif

    return Router::StartRoutingIpv6();
}

bool IpcServer::StopRoutingIpv6()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::StopRoutingIpv6";
#endif

    return Router::StopRoutingIpv6();
}

void IpcServer::setLogsEnabled(bool enabled)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::setLogsEnabled";
#endif

    if (enabled) {
        Logger::init(true);
    } else {
        Logger::deInit();
    }
}

bool IpcServer::startNetworkCheck(const QString& serverIpv4Gateway, const QString& deviceIpv4Address)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::startNetworkCheck";
#endif

    m_pingHelper.start(serverIpv4Gateway, deviceIpv4Address);
    return true;
}

bool IpcServer::stopNetworkCheck()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::stopNetworkCheck";
#endif

    m_pingHelper.stop();
    return true;
}

bool IpcServer::resetKillSwitchAllowedRange(QStringList ranges)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::resetKillSwitchAllowedRange";
#endif

    return KillSwitch::instance()->resetAllowedRange(ranges);
}

bool IpcServer::addKillSwitchAllowedRange(QStringList ranges)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::addKillSwitchAllowedRange";
#endif

    return KillSwitch::instance()->addAllowedRange(ranges);
}

bool IpcServer::disableAllTraffic()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::disableAllTraffic";
#endif

    return KillSwitch::instance()->disableAllTraffic();
}

bool IpcServer::enableKillSwitch(const QJsonObject &configStr, int vpnAdapterIndex)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::enableKillSwitch";
#endif

    return KillSwitch::instance()->enableKillSwitch(configStr, vpnAdapterIndex);
}

bool IpcServer::disableKillSwitch()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::disableKillSwitch";
#endif

    return KillSwitch::instance()->disableKillSwitch();
}

bool IpcServer::enablePeerTraffic(const QJsonObject &configStr)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::enablePeerTraffic";
#endif

    return KillSwitch::instance()->enablePeerTraffic(configStr);
}

bool IpcServer::refreshKillSwitch(bool enabled)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::refreshKillSwitch";
#endif

    return KillSwitch::instance()->refresh(enabled);
}

bool IpcServer::xrayStart(const QString& cfg)
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::xrayStart";
#endif

    return Xray::getInstance().startXray(cfg);
}

bool IpcServer::xrayStop()
{
#ifdef MZ_DEBUG
    qDebug() << "IpcServer::xrayStop";
#endif

    return Xray::getInstance().stopXray();
}
