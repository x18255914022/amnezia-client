/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "daemonlocalserver.h"

#include <QDir>
#include <QFileInfo>
#include <QLocalSocket>

#include "daemonlocalserverconnection.h"
#include "leakdetector.h"
#include "logger.h"

#if defined(MZ_MACOS) || defined(MZ_LINUX)
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <unistd.h>


constexpr const char* VAR_PATH = "/var/run/amneziavpn/daemon.socket";
#endif

namespace {
Logger logger("DaemonLocalServer");
}  // namespace

DaemonLocalServer::DaemonLocalServer(QObject* parent) : QObject(parent) {
  MZ_COUNT_CTOR(DaemonLocalServer);
}

DaemonLocalServer::~DaemonLocalServer() { MZ_COUNT_DTOR(DaemonLocalServer); }

bool DaemonLocalServer::initialize() {
  // SECURITY: do not grant world access to the daemon socket. The daemon
  // performs privileged network operations as root; arbitrary local processes
  // must not be able to drive it. Only the trusted desktop client connects,
  // and the socket lives in a restricted directory (see daemonPath()).
  m_server.setSocketOptions(QLocalServer::UserAccessOption);

  QString path = daemonPath();
  if (path.isEmpty()) {
    logger.error() << "No secure daemon socket path available";
    return false;
  }
  logger.debug() << "Server path:" << path;

  if (QFileInfo::exists(path)) {
    QFile::remove(path);
  }

  if (!m_server.listen(path)) {
    logger.error() << "Failed to listen the daemon path";
    return false;
  }

#if defined(MZ_LINUX) || defined(MZ_MACOS)
  // Restrict the socket file itself to the owner (root).
  if (chmod(path.toLocal8Bit().constData(), S_IRUSR | S_IWUSR) < 0) {
    logger.warning() << "Failed to set permissions on the daemon socket";
  }
#endif

  connect(&m_server, &QLocalServer::newConnection, [&] {
    logger.debug() << "New connection received";

    if (!m_server.hasPendingConnections()) {
      return;
    }

    QLocalSocket* socket = m_server.nextPendingConnection();
    Q_ASSERT(socket);

    DaemonLocalServerConnection* connection =
        new DaemonLocalServerConnection(&m_server, socket);
    connect(socket, &QLocalSocket::disconnected, connection,
            &DaemonLocalServerConnection::deleteLater);
  });

  return true;
}

QString DaemonLocalServer::daemonPath() const {
#if defined(MZ_WINDOWS)
  return "\\\\.\\pipe\\amneziavpn";
#endif
#if defined(MZ_MACOS) || defined(MZ_LINUX)
  // SECURITY: never expose the control socket in a world-writable location
  // such as /tmp: any local user could connect to it and drive the root
  // daemon (install/remove VPN tunnels, modify routing). The daemon runs as
  // root and cannot know the uid of the desktop user that connects, so the
  // only safe location is a root-owned directory with restricted access.
  QDir dir("/var/run");
  if (!dir.exists()) {
    logger.error() << "/var/run doesn't exist; the daemon socket path is not"
                   << "available. Refusing to fall back to an insecure /tmp"
                   << "socket.";
    return QString();
  }

  if (!dir.exists("amneziavpn")) {
    if (!dir.mkdir("amneziavpn")) {
      logger.error() << "Failed to create /var/run/amneziavpn";
      return QString();
    }
  }

  // Root-owned, not group/other writable. Do NOT widen this to world-access:
  // connections are accepted from the desktop client process only.
  if (chmod("/var/run/amneziavpn", S_IRWXU | S_IXGRP | S_IXOTH) < 0) {
    logger.warning()
        << "Failed to set the right permissions to /var/run/amneziavpn";
    return QString();
  }

  return VAR_PATH;
#endif
}
