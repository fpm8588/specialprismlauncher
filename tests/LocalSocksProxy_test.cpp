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

#include <QSslSocket>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTest>

#include <net/LocalSocksProxy.h>

namespace {

// Stands in for the relay: remembers the CONNECT request, answers with `status`, then echoes what it receives.
class FakeRelay : public QTcpServer {
   public:
    explicit FakeRelay(const QByteArray& status = "200 Connection Established") : m_status(status)
    {
        connect(this, &QTcpServer::newConnection, this, [this] {
            while (auto* socket = nextPendingConnection()) {
                connect(socket, &QTcpSocket::readyRead, socket, [this, socket] { onReadyRead(socket); });
            }
        });
    }

    QUrl baseUrl() const { return QUrl(QString("http://127.0.0.1:%1").arg(serverPort())); }

    QList<QByteArray> requests;

   private:
    void onReadyRead(QTcpSocket* socket)
    {
        if (socket->property("connected").toBool()) {
            socket->write(socket->readAll());
            return;
        }
        QByteArray buffer = socket->property("buffer").toByteArray() + socket->readAll();
        const int end = buffer.indexOf("\r\n\r\n");
        if (end < 0) {
            socket->setProperty("buffer", buffer);
            return;
        }
        requests << buffer.left(end);
        socket->setProperty("connected", true);
        socket->write("HTTP/1.1 " + m_status + "\r\n\r\n");
        const QByteArray rest = buffer.mid(end + 4);
        if (!rest.isEmpty()) {
            socket->write(rest);
        }
    }

    QByteArray m_status;
};

QByteArray socksGreeting()
{
    return QByteArray::fromHex("050100");
}

QByteArray socksConnectDomain(const QByteArray& host, quint16 port)
{
    QByteArray request = QByteArray::fromHex("05010003");
    request += static_cast<char>(host.size()) + host;
    request += static_cast<char>(port >> 8);
    request += static_cast<char>(port & 0xff);
    return request;
}

QByteArray socksConnectIPv4(quint8 a, quint8 b, quint8 c, quint8 d, quint16 port)
{
    QByteArray request = QByteArray::fromHex("05010001");
    request += static_cast<char>(a);
    request += static_cast<char>(b);
    request += static_cast<char>(c);
    request += static_cast<char>(d);
    request += static_cast<char>(port >> 8);
    request += static_cast<char>(port & 0xff);
    return request;
}

// A real TLS ClientHello for `name`, captured by letting a QSslSocket talk to a server that only listens.
QByteArray captureClientHello(const QString& name)
{
    QTcpServer server;
    if (!server.listen(QHostAddress::LocalHost, 0)) {
        return {};
    }
    QByteArray hello;
    QObject::connect(&server, &QTcpServer::newConnection, &server, [&] {
        auto* socket = server.nextPendingConnection();
        QObject::connect(socket, &QTcpSocket::readyRead, socket, [&hello, socket] { hello += socket->readAll(); });
    });
    QSslSocket client;
    client.connectToHostEncrypted("127.0.0.1", server.serverPort(), name.isEmpty() ? QString() : name);
    const bool gotHello = QTest::qWaitFor([&] { return hello.size() > 5; }, 5000);
    Q_UNUSED(gotHello)
    client.abort();
    return hello;
}

// Reads from `socket` until `count` bytes are there or the peer closes. Returns what arrived.
QByteArray readExactly(QTcpSocket& socket, qsizetype count, int timeoutMs = 5000)
{
    QByteArray data;
    const bool done = QTest::qWaitFor(
        [&] {
            data += socket.readAll();
            return data.size() >= count || socket.state() != QAbstractSocket::ConnectedState;
        },
        timeoutMs);
    Q_UNUSED(done)
    data += socket.readAll();
    return data;
}

}  // namespace

class LocalSocksProxyTest : public QObject {
    Q_OBJECT

   private slots:
    void clientHelloGivesTheServerName()
    {
        const QByteArray hello = captureClientHello("sessionserver.mojang.com");
        QVERIFY(hello.size() > 5);
        QString name;
        QCOMPARE(LocalSocksProxy::parseClientHello(hello, &name), LocalSocksProxy::HelloState::Found);
        QCOMPARE(name, QString("sessionserver.mojang.com"));
    }

    void incompleteClientHelloNeedsMore()
    {
        const QByteArray hello = captureClientHello("sessionserver.mojang.com");
        QVERIFY(hello.size() > 50);
        QString name;
        QCOMPARE(LocalSocksProxy::parseClientHello(QByteArray(), &name), LocalSocksProxy::HelloState::NeedMore);
        QCOMPARE(LocalSocksProxy::parseClientHello(hello.left(3), &name), LocalSocksProxy::HelloState::NeedMore);
        QCOMPARE(LocalSocksProxy::parseClientHello(hello.left(hello.size() - 1), &name), LocalSocksProxy::HelloState::NeedMore);
    }

    void notTlsIsRecognised()
    {
        QString name;
        QCOMPARE(LocalSocksProxy::parseClientHello("GET / HTTP/1.1\r\n\r\n", &name), LocalSocksProxy::HelloState::NotTls);
    }

    void truncatedOrGarbledHelloNeverCrashes()
    {
        const QByteArray hello = captureClientHello("sessionserver.mojang.com");
        QVERIFY(hello.size() > 50);
        // Pretend the record is complete but cut short or damaged inside; the parser must refuse, not read out of bounds.
        for (int cut = 6; cut < hello.size(); cut += 3) {
            QByteArray damaged = hello.left(cut);
            damaged[3] = static_cast<char>((cut - 5) >> 8);
            damaged[4] = static_cast<char>((cut - 5) & 0xff);
            QString name;
            LocalSocksProxy::parseClientHello(damaged, &name);
        }
        for (int i = 5; i < hello.size(); i += 7) {
            QByteArray damaged = hello;
            damaged[i] = static_cast<char>(0xff);
            QString name;
            LocalSocksProxy::parseClientHello(damaged, &name);
        }
    }

    void domainRequestReachesTheRelayWithTheToken()
    {
        FakeRelay relay;
        QVERIFY(relay.listen(QHostAddress::LocalHost, 0));
        LocalSocksProxy proxy;
        QVERIFY(proxy.start(relay.baseUrl(), "secret-token"));
        QVERIFY(proxy.port() != 0);

        QTcpSocket client;
        client.connectToHost(QHostAddress::LocalHost, proxy.port());
        QVERIFY(client.waitForConnected(3000));
        client.write(socksGreeting());
        QCOMPARE(readExactly(client, 2), QByteArray::fromHex("0500"));
        client.write(socksConnectDomain("sessionserver.mojang.com", 443));
        const QByteArray reply = readExactly(client, 10);
        QCOMPARE(reply.size(), 10);
        QCOMPARE(static_cast<quint8>(reply.at(1)), static_cast<quint8>(0));

        client.write("hello through the tunnel");
        QCOMPARE(readExactly(client, 24), QByteArray("hello through the tunnel"));

        QCOMPARE(relay.requests.size(), 1);
        const QByteArray request = relay.requests.first();
        QVERIFY(request.startsWith("CONNECT sessionserver.mojang.com:443 HTTP/1.1\r\n"));
        QVERIFY(request.contains("X-Relay-Token: secret-token"));
    }

    void ipAddressRequestUsesTheNameFromTheTlsHello()
    {
        FakeRelay relay;
        QVERIFY(relay.listen(QHostAddress::LocalHost, 0));
        LocalSocksProxy proxy;
        QVERIFY(proxy.start(relay.baseUrl(), "secret-token"));

        const QByteArray hello = captureClientHello("sessionserver.mojang.com");
        QVERIFY(hello.size() > 5);

        QTcpSocket client;
        client.connectToHost(QHostAddress::LocalHost, proxy.port());
        QVERIFY(client.waitForConnected(3000));
        client.write(socksGreeting());
        QCOMPARE(readExactly(client, 2), QByteArray::fromHex("0500"));
        client.write(socksConnectIPv4(20, 50, 80, 209, 443));
        QCOMPARE(readExactly(client, 10).size(), 10);
        client.write(hello);

        // The relay echoes the handshake bytes back once the tunnel is open.
        QCOMPARE(readExactly(client, hello.size()), hello);
        QCOMPARE(relay.requests.size(), 1);
        QVERIFY(relay.requests.first().startsWith("CONNECT sessionserver.mojang.com:443 HTTP/1.1\r\n"));
    }

    void ipAddressRequestWithoutAServerNameIsRefused()
    {
        FakeRelay relay;
        QVERIFY(relay.listen(QHostAddress::LocalHost, 0));
        LocalSocksProxy proxy;
        QVERIFY(proxy.start(relay.baseUrl(), "secret-token"));

        const QByteArray hello = captureClientHello(QString());  // connecting to an IP sends no server name
        QVERIFY(hello.size() > 5);

        QTcpSocket client;
        client.connectToHost(QHostAddress::LocalHost, proxy.port());
        QVERIFY(client.waitForConnected(3000));
        client.write(socksGreeting());
        QCOMPARE(readExactly(client, 2), QByteArray::fromHex("0500"));
        client.write(socksConnectIPv4(20, 50, 80, 209, 443));
        readExactly(client, 10);
        client.write(hello);
        QVERIFY(QTest::qWaitFor([&] { return client.state() != QAbstractSocket::ConnectedState; }, 3000));
        QVERIFY(relay.requests.isEmpty());
    }

    void onlyPort443IsServed()
    {
        FakeRelay relay;
        QVERIFY(relay.listen(QHostAddress::LocalHost, 0));
        LocalSocksProxy proxy;
        QVERIFY(proxy.start(relay.baseUrl(), "secret-token"));

        QTcpSocket client;
        client.connectToHost(QHostAddress::LocalHost, proxy.port());
        QVERIFY(client.waitForConnected(3000));
        client.write(socksGreeting());
        QCOMPARE(readExactly(client, 2), QByteArray::fromHex("0500"));
        client.write(socksConnectDomain("example.com", 25565));
        const QByteArray reply = readExactly(client, 10);
        QCOMPARE(reply.size(), 10);
        QCOMPARE(static_cast<quint8>(reply.at(1)), static_cast<quint8>(2));
        QVERIFY(relay.requests.isEmpty());
    }

    void relayRefusalClosesTheConnection()
    {
        FakeRelay relay("403 Forbidden");
        QVERIFY(relay.listen(QHostAddress::LocalHost, 0));
        LocalSocksProxy proxy;
        QVERIFY(proxy.start(relay.baseUrl(), "secret-token"));

        QTcpSocket client;
        client.connectToHost(QHostAddress::LocalHost, proxy.port());
        QVERIFY(client.waitForConnected(3000));
        client.write(socksGreeting());
        QCOMPARE(readExactly(client, 2), QByteArray::fromHex("0500"));
        client.write(socksConnectDomain("evil.example", 443));
        readExactly(client, 10);
        client.write("data that must go nowhere");
        QVERIFY(QTest::qWaitFor([&] { return client.state() != QAbstractSocket::ConnectedState; }, 3000));
    }

    void doesNotStartWithoutRelayOrToken()
    {
        LocalSocksProxy proxy;
        QVERIFY(!proxy.start(QUrl(), "token"));
        QVERIFY(!proxy.start(QUrl("http://127.0.0.1:1"), QByteArray()));
        QVERIFY(!proxy.isRunning());
        QCOMPARE(proxy.port(), quint16(0));
    }

    void stopClosesTheListener()
    {
        LocalSocksProxy proxy;
        QVERIFY(proxy.start(QUrl("http://127.0.0.1:1"), "token"));
        QVERIFY(proxy.isRunning());
        proxy.stop();
        QVERIFY(!proxy.isRunning());
    }
};

QTEST_GUILESS_MAIN(LocalSocksProxyTest)

#include "LocalSocksProxy_test.moc"
