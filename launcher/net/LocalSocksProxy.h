// SPDX-License-Identifier: GPL-3.0-only
/*
 *  Prism Launcher - Minecraft Launcher
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 3.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QTcpServer>
#include <QUrl>

/**
 * A tiny SOCKS5 proxy, listening on this computer only, that hands the game's HTTPS connections to the relay.
 *
 * The game (Minecraft's own code, not the launcher) makes some HTTPS requests itself, above all the "join server" call to
 * Mojang's session server when you connect to an online server. It cannot be given a relay address, but it does accept
 * `--proxyHost` and `--proxyPort`, which make it use a SOCKS proxy for exactly those web requests. The connection to the
 * game server itself is a plain socket that never uses it.
 *
 * Each SOCKS connection is turned into an HTTP `CONNECT host:443` request to the relay (carrying the relay token), and the
 * relay opens the connection to the host if it is on its allowlist. Only port 443 is served.
 *
 * Java usually resolves the host name itself and passes the proxy an IP address, so the proxy reads the host name from the
 * TLS handshake (the SNI field of the ClientHello) when it has to.
 */
class LocalSocksProxy : public QObject {
    Q_OBJECT

   public:
    explicit LocalSocksProxy(QObject* parent = nullptr);
    ~LocalSocksProxy() override;

    /** Start listening on 127.0.0.1 (any free port) and send connections through the relay at relayBase. */
    bool start(const QUrl& relayBase, const QByteArray& token);
    void stop();

    bool isRunning() const { return m_server.isListening(); }
    quint16 port() const { return m_server.isListening() ? m_server.serverPort() : 0; }

    enum class HelloState { NeedMore, Found, NoServerName, NotTls };

    /** Read the server name out of a TLS ClientHello. NeedMore means the record is not complete yet. */
    static HelloState parseClientHello(const QByteArray& data, QString* serverName);

   private slots:
    void onNewConnection();

   private:
    class Session;

    QTcpServer m_server;
    QUrl m_relayBase;
    QByteArray m_token;
    int m_sessions = 0;
};
