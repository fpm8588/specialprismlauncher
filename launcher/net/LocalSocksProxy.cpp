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

#include "LocalSocksProxy.h"

#include <QDebug>
#include <QHostAddress>
#include <QRegularExpression>
#include <QSslSocket>
#include <QTcpSocket>
#include <QTimer>

namespace {
constexpr int HANDSHAKE_TIMEOUT_MS = 20000;
constexpr int MAX_SESSIONS = 64;
constexpr qsizetype MAX_BUFFER = 32 * 1024;

QByteArray socksReply(quint8 code)
{
    // VER, REP, RSV, ATYP=IPv4, BND.ADDR (0.0.0.0), BND.PORT (0)
    QByteArray reply(10, '\0');
    reply[0] = 5;
    reply[1] = static_cast<char>(code);
    reply[3] = 1;
    return reply;
}

quint8 byteAt(const QByteArray& data, qsizetype i)
{
    return static_cast<quint8>(data.at(i));
}

bool plausibleHostName(const QString& name)
{
    static const QRegularExpression re(QRegularExpression::anchoredPattern("[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?"));
    return re.match(name).hasMatch();
}
}  // namespace

// ---- TLS ClientHello parsing -------------------------------------------------------------------------------------

LocalSocksProxy::HelloState LocalSocksProxy::parseClientHello(const QByteArray& data, QString* serverName)
{
    // TLS record: type(1)=0x16 handshake, version(2), length(2)
    if (data.isEmpty()) {
        return HelloState::NeedMore;
    }
    if (byteAt(data, 0) != 0x16) {
        return HelloState::NotTls;
    }
    if (data.size() < 5) {
        return HelloState::NeedMore;
    }
    const qsizetype recordLength = (byteAt(data, 3) << 8) | byteAt(data, 4);
    if (data.size() < 5 + recordLength) {
        return HelloState::NeedMore;
    }

    const QByteArray hello = data.mid(5, recordLength);
    qsizetype i = 0;
    auto have = [&](qsizetype n) { return i + n <= hello.size(); };

    // Handshake header: type(1)=1 ClientHello, length(3); then version(2) and random(32)
    if (!have(4) || byteAt(hello, 0) != 0x01) {
        return HelloState::NotTls;
    }
    i = 4 + 2 + 32;
    // session id
    if (!have(1)) return HelloState::NoServerName;
    i += 1 + byteAt(hello, i);
    // cipher suites
    if (!have(2)) return HelloState::NoServerName;
    i += 2 + ((byteAt(hello, i) << 8) | byteAt(hello, i + 1));
    // compression methods
    if (!have(1)) return HelloState::NoServerName;
    i += 1 + byteAt(hello, i);
    // extensions
    if (!have(2)) return HelloState::NoServerName;
    const qsizetype extensionsEnd = qMin<qsizetype>(hello.size(), i + 2 + ((byteAt(hello, i) << 8) | byteAt(hello, i + 1)));
    i += 2;
    while (i + 4 <= extensionsEnd) {
        const int type = (byteAt(hello, i) << 8) | byteAt(hello, i + 1);
        const qsizetype length = (byteAt(hello, i + 2) << 8) | byteAt(hello, i + 3);
        i += 4;
        if (i + length > extensionsEnd) {
            break;
        }
        if (type == 0x0000) {  // server_name
            // list length(2), then entries of: name type(1)=0 host_name, length(2), name
            qsizetype j = i + 2;
            while (j + 3 <= i + length) {
                const int nameType = byteAt(hello, j);
                const qsizetype nameLength = (byteAt(hello, j + 1) << 8) | byteAt(hello, j + 2);
                j += 3;
                if (j + nameLength > i + length) {
                    break;
                }
                if (nameType == 0) {
                    const QString name = QString::fromLatin1(hello.mid(j, nameLength)).toLower();
                    if (plausibleHostName(name)) {
                        if (serverName) *serverName = name;
                        return HelloState::Found;
                    }
                    return HelloState::NoServerName;
                }
                j += nameLength;
            }
        }
        i += length;
    }
    return HelloState::NoServerName;
}

// ---- one SOCKS connection ----------------------------------------------------------------------------------------

class LocalSocksProxy::Session : public QObject {
    Q_OBJECT

   public:
    Session(QTcpSocket* client, const QUrl& relay, const QByteArray& token, QObject* parent)
        : QObject(parent), m_client(client), m_relayBase(relay), m_token(token)
    {
        m_client->setParent(this);
        connect(m_client, &QTcpSocket::readyRead, this, &Session::onClientReadyRead);
        connect(m_client, &QTcpSocket::disconnected, this, &Session::finish);
        connect(m_client, &QTcpSocket::errorOccurred, this, [this] { finish(); });

        m_timer.setSingleShot(true);
        connect(&m_timer, &QTimer::timeout, this, &Session::finish);
        m_timer.start(HANDSHAKE_TIMEOUT_MS);
    }

   private slots:
    void onClientReadyRead()
    {
        if (m_state == State::Pumping) {
            m_relay->write(m_client->readAll());
            return;
        }
        m_buffer += m_client->readAll();
        if (m_buffer.size() > MAX_BUFFER) {
            finish();
            return;
        }
        advance();
    }

    void onRelayConnected()
    {
        const QByteArray target = m_host.toLatin1() + ":443";
        QByteArray request = "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\nX-Relay-Token: " + m_token +
                             "\r\nUser-Agent: PrismLauncher-game-login\r\n\r\n";
        m_relay->write(request);
        m_state = State::WaitingRelayReply;
    }

    void onRelayReadyRead()
    {
        if (m_state == State::Pumping) {
            m_client->write(m_relay->readAll());
            return;
        }
        if (m_state != State::WaitingRelayReply) {
            return;
        }
        m_relayBuffer += m_relay->readAll();
        const qsizetype end = m_relayBuffer.indexOf("\r\n\r\n");
        if (end < 0) {
            if (m_relayBuffer.size() > 8192) finish();
            return;
        }
        const QByteArray statusLine = m_relayBuffer.left(m_relayBuffer.indexOf("\r\n"));
        const QList<QByteArray> parts = statusLine.split(' ');
        if (parts.size() < 2 || parts.at(1) != "200") {
            qWarning() << "The relay refused to open a connection to" << m_host << ":" << statusLine;
            finish();
            return;
        }
        const QByteArray leftover = m_relayBuffer.mid(end + 4);
        m_state = State::Pumping;
        m_timer.stop();
        if (!leftover.isEmpty()) {
            m_client->write(leftover);
        }
        if (!m_buffer.isEmpty()) {  // the TLS handshake the game already sent
            m_relay->write(m_buffer);
            m_buffer.clear();
        }
        if (m_client->bytesAvailable() > 0) {
            m_relay->write(m_client->readAll());
        }
    }

    void finish()
    {
        if (m_state == State::Closed) {
            return;
        }
        m_state = State::Closed;
        m_timer.stop();
        if (m_relay) {
            m_relay->disconnect(this);
            m_relay->abort();
        }
        m_client->disconnect(this);
        m_client->disconnectFromHost();
        if (m_client->state() == QAbstractSocket::UnconnectedState) {
            deleteLater();
        } else {
            // A last reply (the SOCKS error code) may still be waiting to be sent; let it go out before the socket is deleted.
            connect(m_client, &QTcpSocket::disconnected, this, &Session::deleteLater);
            QTimer::singleShot(2000, this, &Session::deleteLater);
        }
    }

   private:
    enum class State { Greeting, Request, WaitingHello, ConnectingRelay, WaitingRelayReply, Pumping, Closed };

    void advance()
    {
        if (m_state == State::Greeting) {
            // VER(1)=5, NMETHODS(1), METHODS(n)
            if (m_buffer.size() < 2 || m_buffer.size() < 2 + byteAt(m_buffer, 1)) {
                return;
            }
            const int methods = byteAt(m_buffer, 1);
            if (byteAt(m_buffer, 0) != 5 || !m_buffer.mid(2, methods).contains('\0')) {
                m_client->write(QByteArray::fromHex("05ff"));  // no acceptable method
                finish();
                return;
            }
            m_buffer.remove(0, 2 + methods);
            m_client->write(QByteArray::fromHex("0500"));  // no authentication: only this computer can connect
            m_state = State::Request;
        }

        if (m_state == State::Request) {
            // VER(1) CMD(1) RSV(1) ATYP(1) ADDR(n) PORT(2)
            if (m_buffer.size() < 5) {
                return;
            }
            const int atyp = byteAt(m_buffer, 3);
            qsizetype total = 0;
            if (atyp == 1) total = 4 + 4 + 2;
            else if (atyp == 3) total = 4 + 1 + byteAt(m_buffer, 4) + 2;
            else if (atyp == 4) total = 4 + 16 + 2;
            else {
                refuse(0x08);  // address type not supported
                return;
            }
            if (m_buffer.size() < total) {
                return;
            }
            if (byteAt(m_buffer, 0) != 5 || byteAt(m_buffer, 1) != 1) {
                refuse(0x07);  // only CONNECT
                return;
            }
            const int port = (byteAt(m_buffer, total - 2) << 8) | byteAt(m_buffer, total - 1);
            if (port != 443) {
                refuse(0x02);  // not allowed: this proxy is only for HTTPS
                return;
            }
            QString domain;
            if (atyp == 3) {
                domain = QString::fromLatin1(m_buffer.mid(5, byteAt(m_buffer, 4))).toLower();
            }
            m_buffer.remove(0, total);
            m_client->write(socksReply(0x00));  // succeeded: the TLS handshake follows
            if (!domain.isEmpty() && plausibleHostName(domain)) {
                openRelay(domain);
                return;
            }
            m_state = State::WaitingHello;
        }

        if (m_state == State::WaitingHello) {
            QString name;
            switch (parseClientHello(m_buffer, &name)) {
                case HelloState::NeedMore:
                    return;
                case HelloState::Found:
                    openRelay(name);
                    return;
                case HelloState::NoServerName:
                case HelloState::NotTls:
                    qWarning() << "Game login proxy: connection without a host name, refusing it";
                    finish();
                    return;
            }
        }
    }

    void refuse(quint8 code)
    {
        m_client->write(socksReply(code));
        finish();
    }

    void openRelay(const QString& host)
    {
        m_host = host;
        m_state = State::ConnectingRelay;
        m_relay = new QSslSocket(this);
        const bool https = m_relayBase.scheme() == "https";
        if (https) {
            connect(m_relay, &QSslSocket::encrypted, this, &Session::onRelayConnected);
        } else {
            connect(m_relay, &QSslSocket::connected, this, &Session::onRelayConnected);
        }
        connect(m_relay, &QSslSocket::readyRead, this, &Session::onRelayReadyRead);
        connect(m_relay, &QSslSocket::disconnected, this, &Session::finish);
        connect(m_relay, &QSslSocket::errorOccurred, this, [this] { finish(); });
        connect(m_relay, &QSslSocket::sslErrors, this, [this](const QList<QSslError>& errors) {
            qWarning() << "Game login proxy: the relay's certificate was rejected:" << errors.value(0).errorString();
            finish();
        });
        const quint16 port = static_cast<quint16>(m_relayBase.port(https ? 443 : 80));
        if (https) {
            m_relay->connectToHostEncrypted(m_relayBase.host(), port);
        } else {
            m_relay->connectToHost(m_relayBase.host(), port);
        }
    }

    QTcpSocket* m_client;
    QSslSocket* m_relay = nullptr;
    QUrl m_relayBase;
    QByteArray m_token;
    QByteArray m_buffer;       // what the game has sent that has not been passed on yet
    QByteArray m_relayBuffer;  // the relay's reply while its header is incomplete
    QString m_host;
    State m_state = State::Greeting;
    QTimer m_timer;
};

// ---- the listening side ------------------------------------------------------------------------------------------

LocalSocksProxy::LocalSocksProxy(QObject* parent) : QObject(parent)
{
    connect(&m_server, &QTcpServer::newConnection, this, &LocalSocksProxy::onNewConnection);
}

LocalSocksProxy::~LocalSocksProxy()
{
    stop();
}

bool LocalSocksProxy::start(const QUrl& relayBase, const QByteArray& token)
{
    stop();
    if (!relayBase.isValid() || relayBase.host().isEmpty() || token.isEmpty()) {
        return false;
    }
    m_relayBase = relayBase;
    m_token = token;
    if (!m_server.listen(QHostAddress::LocalHost, 0)) {
        qWarning() << "Game login proxy could not start:" << m_server.errorString();
        return false;
    }
    qInfo() << "Game login proxy listening on 127.0.0.1:" << m_server.serverPort();
    return true;
}

void LocalSocksProxy::stop()
{
    if (m_server.isListening()) {
        m_server.close();
    }
    for (Session* session : findChildren<Session*>(Qt::FindDirectChildrenOnly)) {
        session->deleteLater();
    }
}

void LocalSocksProxy::onNewConnection()
{
    while (QTcpSocket* socket = m_server.nextPendingConnection()) {
        if (!socket->peerAddress().isLoopback() || m_sessions >= MAX_SESSIONS) {
            socket->abort();
            socket->deleteLater();
            continue;
        }
        auto* session = new Session(socket, m_relayBase, m_token, this);
        ++m_sessions;
        connect(session, &QObject::destroyed, this, [this] { --m_sessions; });
    }
}

#include "LocalSocksProxy.moc"
