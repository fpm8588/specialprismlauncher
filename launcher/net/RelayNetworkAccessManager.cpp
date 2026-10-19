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

#include "RelayNetworkAccessManager.h"

#include <QDebug>
#include <QHostAddress>
#include <QNetworkRequest>

namespace {
bool isLoopbackHost(const QString& host)
{
    if (host.compare("localhost", Qt::CaseInsensitive) == 0) {
        return true;
    }
    QHostAddress address;
    return address.setAddress(host) && address.isLoopback();
}

int effectivePort(const QUrl& url)
{
    return url.port(url.scheme() == "http" ? 80 : 443);
}

// Requests made while the relay configuration is unusable go here. The .invalid TLD never resolves (RFC 2606),
// so they fail with a clear "host not found" instead of reaching Mojang or Microsoft directly.
const QUrl FAIL_CLOSED_URL("https://relay-not-configured.invalid/");
}  // namespace

RelayNetworkAccessManager::RelayNetworkAccessManager(QObject* parent) : QNetworkAccessManager(parent) {}

void RelayNetworkAccessManager::configure(const QString& relayUrl, const QString& token)
{
    m_relayBase.clear();
    m_token.clear();

    const QString trimmedUrl = relayUrl.trimmed();
    if (trimmedUrl.isEmpty()) {
        m_mode = Mode::Direct;
        return;
    }

    const QUrl base(trimmedUrl, QUrl::StrictMode);
    const bool schemeOk = base.scheme() == "https" || (base.scheme() == "http" && isLoopbackHost(base.host()));
    if (!base.isValid() || base.host().isEmpty() || !schemeOk) {
        qWarning() << "Relay URL is not usable (it must be an https:// URL); all network requests will fail until it is fixed:" << trimmedUrl;
        m_mode = Mode::FailClosed;
        return;
    }
    if (token.trimmed().isEmpty()) {
        qWarning() << "A relay is configured but no relay token is set; all network requests will fail until it is set.";
        m_mode = Mode::FailClosed;
        return;
    }

    m_relayBase = base;
    m_token = token.trimmed().toUtf8();
    m_mode = Mode::Relay;
    qInfo() << "Network requests are routed through the relay at" << m_relayBase.toString(QUrl::RemoveUserInfo | QUrl::RemoveQuery);
}

QUrl RelayNetworkAccessManager::rewriteForRelay(const QUrl& original, const QUrl& relayBase)
{
    const QString scheme = original.scheme();
    if (scheme != "https" && scheme != "http") {
        return {};  // file:, qrc:, data: ... never leave the machine
    }

    const QString host = original.host(QUrl::FullyEncoded).toLower();  // ACE form for internationalised names
    if (host.isEmpty() || isLoopbackHost(host)) {
        return {};
    }
    if (host == relayBase.host(QUrl::FullyEncoded).toLower() && effectivePort(original) == effectivePort(relayBase)) {
        return {};  // already addressed to the relay
    }

    // The relay always talks https upstream, so port 80 on an http URL is the default port as well.
    const int defaultPort = scheme == "http" ? 80 : 443;
    QByteArray hostPort = host.toUtf8();
    if (original.port() != -1 && original.port() != defaultPort) {
        hostPort += ':' + QByteArray::number(original.port());
    }

    // "/path?query" exactly as the caller encoded it.
    QByteArray pathAndQuery = original.toEncoded(QUrl::RemoveScheme | QUrl::RemoveAuthority | QUrl::RemoveFragment);
    if (!pathAndQuery.startsWith('/')) {
        pathAndQuery.prepend('/');
    }

    QByteArray basePath = relayBase.path(QUrl::FullyEncoded).toUtf8();
    while (basePath.endsWith('/')) {
        basePath.chop(1);
    }

    QByteArray relayed = relayBase.scheme().toUtf8() + "://" + relayBase.authority(QUrl::FullyEncoded | QUrl::RemoveUserInfo).toUtf8() +
                         basePath + "/r/" + hostPort + pathAndQuery;
    return QUrl::fromEncoded(relayed);
}

QNetworkReply* RelayNetworkAccessManager::createRequest(Operation op, const QNetworkRequest& request, QIODevice* outgoingData)
{
    if (m_mode == Mode::Direct) {
        return QNetworkAccessManager::createRequest(op, request, outgoingData);
    }

    QNetworkRequest forwarded(request);
    if (m_mode == Mode::FailClosed) {
        // Local-only schemes are harmless; everything else must not go out.
        if (request.url().scheme() == "http" || request.url().scheme() == "https") {
            forwarded.setUrl(FAIL_CLOSED_URL);
        }
        return QNetworkAccessManager::createRequest(op, forwarded, outgoingData);
    }

    const QUrl target = rewriteForRelay(request.url(), m_relayBase);
    if (!target.isEmpty()) {
        forwarded.setUrl(target);
        forwarded.setRawHeader(TOKEN_HEADER, m_token);
    }
    return QNetworkAccessManager::createRequest(op, forwarded, outgoingData);
}
