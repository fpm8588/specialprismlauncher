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

#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QSignalSpy>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTest>

#include <net/RelayNetworkAccessManager.h>

namespace {

// Minimal HTTP server standing in for the relay: records requests and answers 200 "ok".
class FakeRelay : public QTcpServer {
   public:
    FakeRelay()
    {
        connect(this, &QTcpServer::newConnection, this, [this] {
            while (auto* socket = nextPendingConnection()) {
                connect(socket, &QTcpSocket::readyRead, socket, [this, socket] { onReadyRead(socket); });
            }
        });
    }

    QUrl baseUrl() const { return QUrl(QString("http://127.0.0.1:%1").arg(serverPort())); }

    QList<QByteArray> requests;  // header block + body of every request received

   private:
    void onReadyRead(QTcpSocket* socket)
    {
        QByteArray buffer = socket->property("buffer").toByteArray() + socket->readAll();
        socket->setProperty("buffer", buffer);

        const int headerEnd = buffer.indexOf("\r\n\r\n");
        if (headerEnd < 0) {
            return;
        }
        static const QRegularExpression contentLength("content-length:\\s*(\\d+)", QRegularExpression::CaseInsensitiveOption);
        const auto match = contentLength.match(QString::fromLatin1(buffer.left(headerEnd)));
        const qsizetype bodyLength = match.hasMatch() ? match.captured(1).toLongLong() : 0;
        if (buffer.size() < headerEnd + 4 + bodyLength) {
            return;
        }

        requests.append(buffer);
        socket->setProperty("buffer", QByteArray());
        socket->write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        socket->disconnectFromHost();
    }
};

QNetworkReply* waitFor(QNetworkReply* reply)
{
    QSignalSpy spy(reply, &QNetworkReply::finished);
    if (!spy.wait(10000)) {
        qWarning() << "request did not finish";
    }
    return reply;
}

}  // namespace

class RelayNetworkAccessManagerTest : public QObject {
    Q_OBJECT

   private slots:
    void rewrite_data()
    {
        QTest::addColumn<QString>("original");
        QTest::addColumn<QString>("relay");
        QTest::addColumn<QString>("expected");  // empty: must not be relayed

        const QString relay = "https://home.example.com";
        QTest::newRow("library jar") << "https://libraries.minecraft.net/com/google/guava/guava/17.0/guava-17.0.jar" << relay
                                     << "https://home.example.com/r/libraries.minecraft.net/com/google/guava/guava/17.0/guava-17.0.jar";
        QTest::newRow("query is kept as encoded")
            << "https://api.minecraftservices.com/entitlements/license?requestId=a%2Bb&x=1" << relay
            << "https://home.example.com/r/api.minecraftservices.com/entitlements/license?requestId=a%2Bb&x=1";
        QTest::newRow("encoded path is kept") << "https://example.com/a%20b/c%2Fd" << relay
                                              << "https://home.example.com/r/example.com/a%20b/c%2Fd";
        QTest::newRow("no path") << "https://api.modrinth.com" << relay << "https://home.example.com/r/api.modrinth.com/";
        QTest::newRow("query without path") << "https://api.modrinth.com?x=1" << relay << "https://home.example.com/r/api.modrinth.com/?x=1";
        QTest::newRow("fragment dropped") << "https://example.com/p#frag" << relay << "https://home.example.com/r/example.com/p";
        QTest::newRow("host lowercased") << "https://Libraries.Minecraft.NET/x" << relay << "https://home.example.com/r/libraries.minecraft.net/x";
        QTest::newRow("non-default port") << "https://example.com:8443/x" << relay << "https://home.example.com/r/example.com:8443/x";
        QTest::newRow("default port dropped") << "https://example.com:443/x" << relay << "https://home.example.com/r/example.com/x";
        QTest::newRow("http is relayed as https") << "http://textures.minecraft.net/texture/abc" << relay
                                                  << "https://home.example.com/r/textures.minecraft.net/texture/abc";
        QTest::newRow("plain-http relay") << "https://libraries.minecraft.net/x.jar" << "http://203.0.113.9:8080"
                                         << "http://203.0.113.9:8080/r/libraries.minecraft.net/x.jar";
        QTest::newRow("relay with path prefix and port")
            << "https://piston-meta.mojang.com/v1/packages/abc/manifest.json" << "https://home.example.com:8443/prism/"
            << "https://home.example.com:8443/prism/r/piston-meta.mojang.com/v1/packages/abc/manifest.json";
        QTest::newRow("other port on the relay host is still relayed") << "https://home.example.com:8443/x" << relay
                                                                        << "https://home.example.com/r/home.example.com:8443/x";

        QTest::newRow("relay itself") << "https://home.example.com/healthz" << relay << "";
        QTest::newRow("localhost") << "http://localhost:1234/callback" << relay << "";
        QTest::newRow("loopback ip") << "http://127.0.0.1:1234/callback" << relay << "";
        QTest::newRow("ipv6 loopback") << "http://[::1]:1234/callback" << relay << "";
        QTest::newRow("file url") << "file:///tmp/x" << relay << "";
        QTest::newRow("qrc url") << "qrc:/icons/x.png" << relay << "";
    }

    void rewrite()
    {
        QFETCH(QString, original);
        QFETCH(QString, relay);
        QFETCH(QString, expected);

        const QUrl result = RelayNetworkAccessManager::rewriteForRelay(QUrl(original), QUrl(relay));
        if (expected.isEmpty()) {
            QVERIFY2(result.isEmpty(), qPrintable(result.toString()));
        } else {
            QCOMPARE(QString::fromLatin1(result.toEncoded()), expected);
        }
    }

    void configure_states()
    {
        RelayNetworkAccessManager manager;
        QVERIFY(!manager.routesThroughRelay());  // default: behaves like stock Prism

        manager.configure("", "whatever");
        QVERIFY(!manager.routesThroughRelay());

        manager.configure("https://home.example.com", "a-token");
        QVERIFY(manager.relayReady());

        manager.configure("https://home.example.com", "   ");  // no token
        QVERIFY(manager.routesThroughRelay());
        QVERIFY(!manager.relayReady());

        manager.configure("http://home.example.com", "a-token");  // plain http is allowed for any address (the owner's choice)
        QVERIFY(manager.relayReady());

        manager.configure("ftp://home.example.com", "a-token");  // other schemes are not
        QVERIFY(manager.routesThroughRelay());
        QVERIFY(!manager.relayReady());

        manager.configure("not a url", "a-token");
        QVERIFY(manager.routesThroughRelay());
        QVERIFY(!manager.relayReady());

        manager.configure("http://127.0.0.1:9999", "a-token");  // loopback http is allowed for local testing
        QVERIFY(manager.relayReady());

        manager.configure("", "");  // switching it off again
        QVERIFY(!manager.routesThroughRelay());
    }

    void requests_go_to_the_relay()
    {
        FakeRelay relay;
        QVERIFY(relay.listen(QHostAddress::LocalHost));

        RelayNetworkAccessManager manager;
        manager.configure(relay.baseUrl().toString(), "secret-token-value");
        QVERIFY(manager.relayReady());

        // GET: path, query and caller headers survive; the token is added.
        QNetworkRequest get(QUrl("https://libraries.minecraft.net/com/mojang/authlib/1.5.21/authlib-1.5.21.jar?x=1"));
        get.setRawHeader("Authorization", "Bearer abc");
        std::unique_ptr<QNetworkReply> reply(waitFor(manager.get(get)));
        QCOMPARE(reply->error(), QNetworkReply::NoError);
        QCOMPARE(reply->readAll(), QByteArray("ok"));
        QCOMPARE(relay.requests.size(), 1);
        const QByteArray first = relay.requests.at(0);
        QVERIFY2(first.startsWith("GET /r/libraries.minecraft.net/com/mojang/authlib/1.5.21/authlib-1.5.21.jar?x=1 HTTP/1.1"), first.constData());
        QVERIFY(first.contains("X-Relay-Token: secret-token-value"));
        QVERIFY(first.contains("Authorization: Bearer abc"));

        // POST: the body is sent to the relay too.
        QNetworkRequest post(QUrl("https://api.minecraftservices.com/launcher/login"));
        post.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
        std::unique_ptr<QNetworkReply> postReply(waitFor(manager.post(post, QByteArray("{\"platform\":\"PC_LAUNCHER\"}"))));
        QCOMPARE(postReply->error(), QNetworkReply::NoError);
        QCOMPARE(relay.requests.size(), 2);
        const QByteArray second = relay.requests.at(1);
        QVERIFY2(second.startsWith("POST /r/api.minecraftservices.com/launcher/login HTTP/1.1"), second.constData());
        QVERIFY(second.endsWith("{\"platform\":\"PC_LAUNCHER\"}"));
    }

    void relay_itself_gets_no_rewrite_and_no_token_leak()
    {
        FakeRelay relay;
        QVERIFY(relay.listen(QHostAddress::LocalHost));

        RelayNetworkAccessManager manager;
        manager.configure(relay.baseUrl().toString(), "secret-token-value");

        // A request that is already addressed to loopback is not relayed, and must not carry the relay token.
        std::unique_ptr<QNetworkReply> reply(waitFor(manager.get(QNetworkRequest(relay.baseUrl().resolved(QUrl("/direct"))))));
        QCOMPARE(relay.requests.size(), 1);
        QVERIFY(relay.requests.at(0).startsWith("GET /direct HTTP/1.1"));
        QVERIFY(!relay.requests.at(0).contains("X-Relay-Token"));
    }

    void misconfigured_relay_fails_closed()
    {
        FakeRelay relay;  // proves nothing is sent anywhere reachable
        QVERIFY(relay.listen(QHostAddress::LocalHost));

        RelayNetworkAccessManager manager;
        manager.configure("https://home.example.com", "");  // no token => fail closed

        std::unique_ptr<QNetworkReply> reply(waitFor(manager.get(QNetworkRequest(QUrl("https://libraries.minecraft.net/x.jar")))));
        QVERIFY2(reply->error() != QNetworkReply::NoError, "a request must not succeed while the relay is misconfigured");
        QVERIFY(reply->url().host().endsWith(".invalid"));  // it never targeted the real host
        QCOMPARE(relay.requests.size(), 0);
    }
};

QTEST_GUILESS_MAIN(RelayNetworkAccessManagerTest)

#include "RelayNetworkAccessManager_test.moc"
