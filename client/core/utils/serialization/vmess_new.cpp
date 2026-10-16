// Copyright (c) Qv2ray, A Qt frontend for V2Ray. Written in C++.
// This file is part of the Qv2ray VPN client.
//
// Qv2ray, A Qt frontend for V2Ray. Written in C++

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// Copyright (c) 2024 AmneziaVPN
// This file has been modified for AmneziaVPN
//
// This file is based on the work of the Qv2ray VPN client.
// The original code of the Qv2ray, A Qt frontend for V2Ray. Written in C++ and licensed under GPL3.
//
// The modified version of this file is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this file. If not, see <https://www.gnu.org/licenses/>.

#include "3rd/QJsonStruct/QJsonIO.hpp"
#include "3rd/QJsonStruct/QJsonStruct.hpp"
#include "transfer.h"
#include "serialization.h"

#include <QUrlQuery>
#include <QUuid>

#define OUTBOUND_TAG_PROXY "PROXY"

namespace amnezia::serialization::vmess_new
{
const static QStringList NetworkType{ "tcp", "http", "ws", "kcp", "quic", "grpc" };
const static QStringList QuicSecurityTypes{ "none", "aes-128-gcm", "chacha20-poly1305" };
const static QStringList QuicKcpHeaderTypes{ "none", "srtp", "utp", "wechat-video", "dtls", "wireguard" };
const static QStringList TcpHeaderTypes{ "none", "srtp", "utp", "wechat-video", "dtls", "wireguard", "http" };
// Allow-list: TLS certificate verification is disabled ONLY for explicitly truthy values.
// Anything else (including typos like "FALSE", "no", "0") keeps verification enabled (fail-closed).
const static QStringList TrueTypes{ "true", "1", "yes", "y" };

QJsonObject Deserialize(const QString &vmessStr, QString *alias, QString *errMessage)
{
    QUrl url{ vmessStr };
    QUrlQuery query{ url };
    //
#define default QJsonObject()
    if (!url.isValid())
    {
        *errMessage = QObject::tr("vmess:// url is invalid");
        return default;
    }

    // If previous alias is empty, just the PS is needed, else, append a "_"
    const auto name = url.fragment(QUrl::FullyDecoded).trimmed();
    *alias = alias->isEmpty() ? name : (*alias + "_" + name);

    VMessServerObject server;
    server.users << VMessServerObject::UserObject{};

    StreamSettingsObject stream;
    QString net;
    bool tls = false;
    // Check streamSettings
    {
        QString netRaw;
        for (const auto &_protocol : url.userName().split("+"))
        {
            if (_protocol.compare("tls", Qt::CaseInsensitive) == 0)
                tls = true;
            else
                netRaw = _protocol;
        }
        net = netRaw.trimmed().toLower();
        if (!NetworkType.contains(net))
        {
            *errMessage = QObject::tr("Invalid streamSettings protocol: ") + net;
            return default;
        }
        stream.network = net;
        stream.security = tls ? "tls" : "";
    }
    // Host Port UUID AlterID
    {
        const auto host = url.host();
        if (host.isEmpty())
        {
            *errMessage = QObject::tr("vmess:// link has no host");
            return default;
        }

        int port = url.port();
        if (port < 1 || port > 65535)
        {
            *errMessage = QObject::tr("Invalid port: ") + QString::number(port);
            return default;
        }

        QString uuid;
        int aid = 0;
        {
            const auto pswd = url.password();
            const auto index = pswd.lastIndexOf("-");
            if (index < 0)
            {
                *errMessage = QObject::tr("Invalid vmess:// userinfo: missing alterId");
                return default;
            }
            uuid = pswd.mid(0, index).trimmed();

            bool aidOk = false;
            aid = pswd.mid(index + 1).toInt(&aidOk);
            if (!aidOk || aid < 0 || aid > 64)
            {
                *errMessage = QObject::tr("Invalid alterId");
                return default;
            }

            if (QUuid(uuid).isNull())
            {
                *errMessage = QObject::tr("Invalid user ID (UUID): ") + uuid;
                return default;
            }
        }
        server.address = host;
        server.port = port;
        server.users.first().id = uuid;
        server.users.first().alterId = aid;
        server.users.first().security = "auto";
    }

    const auto getQueryValue = [&query](const QString &key, const QString &defaultValue) {
        // Case-insensitive lookup: some generators use different letter casing in query keys.
        const auto items = query.queryItems(QUrl::FullyDecoded);
        for (const auto &item : items)
        {
            if (item.first.compare(key, Qt::CaseInsensitive) == 0)
                return item.second;
        }
        return defaultValue;
    };

    //
    // Begin transport settings parser
    {
        if (net == "tcp")
        {
            const auto headerType = getQueryValue("type", "none");
            if (!TcpHeaderTypes.contains(headerType, Qt::CaseInsensitive))
            {
                *errMessage = QObject::tr("Invalid tcp header type: ") + headerType;
                return default;
            }
            stream.tcpSettings.header.type = headerType;
        }
        else if (net == "http")
        {
            stream.httpSettings.host.append(getQueryValue("host", ""));
            stream.httpSettings.path = getQueryValue("path", "/");
        }
        else if (net == "ws")
        {
            stream.wsSettings.headers["Host"] = getQueryValue("host", "");
            stream.wsSettings.path = getQueryValue("path", "/");
        }
        else if (net == "kcp")
        {
            stream.kcpSettings.seed = getQueryValue("seed", "");
            const auto headerType = getQueryValue("type", "none");
            if (!QuicKcpHeaderTypes.contains(headerType, Qt::CaseInsensitive))
            {
                *errMessage = QObject::tr("Invalid kcp header type: ") + headerType;
                return default;
            }
            stream.kcpSettings.header.type = headerType;
        }
        else if (net == "quic")
        {
            const auto security = getQueryValue("security", "none");
            if (!QuicSecurityTypes.contains(security, Qt::CaseInsensitive))
            {
                *errMessage = QObject::tr("Invalid quic security type: ") + security;
                return default;
            }
            const auto headerType = getQueryValue("type", "none");
            if (!QuicKcpHeaderTypes.contains(headerType, Qt::CaseInsensitive))
            {
                *errMessage = QObject::tr("Invalid quic header type: ") + headerType;
                return default;
            }
            stream.quicSettings.security = security;
            stream.quicSettings.key = getQueryValue("key", "");
            stream.quicSettings.header.type = headerType;
        }
        else if (net == "grpc")
        {
            stream.grpcSettings.serviceName = getQueryValue("serviceName", "");
        }
        else
        {
            *errMessage = QObject::tr("Unknown transport method: ") + net;
            return default;
        }
    }
#undef default
    if (tls)
    {
        // Fail-closed: certificate verification stays enabled unless the value is explicitly truthy.
        stream.tlsSettings.allowInsecure = TrueTypes.contains(getQueryValue("allowInsecure", "false").trimmed().toLower());
        stream.tlsSettings.serverName = getQueryValue("tlsServerName", "");
    }
    QJsonObject root;
    QJsonObject vConf;
    QJsonArray vnextArray;
    vnextArray.append(server.toJson());
    vConf["vnext"] = vnextArray;
    auto outbound = outbounds::GenerateOutboundEntry(OUTBOUND_TAG_PROXY, "vmess", vConf, stream.toJson());
    QJsonObject inbound = inbounds::GenerateInboundEntry();

    //
    root["outbounds"] = QJsonArray{ outbound };
    root["inbound"] = QJsonArray{ inbound };
    return root;
}

} // namespace amnezia::serialization::vmess_new
