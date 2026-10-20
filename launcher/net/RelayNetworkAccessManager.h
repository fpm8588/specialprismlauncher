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
#include <QNetworkAccessManager>
#include <QUrl>

/**
 * A QNetworkAccessManager that sends every request through a relay server (see relay/ in this repository).
 *
 * A request for  https://libraries.minecraft.net/a/b.jar?x=1  is sent to
 *                <relay>/r/libraries.minecraft.net/a/b.jar?x=1
 * with the shared secret in the X-Relay-Token header. The relay makes the real request and streams the answer back.
 *
 * While a relay is configured this class never lets a request for a remote host go out directly: if the configuration
 * is unusable, requests are sent to a host that cannot resolve instead of falling back to a direct connection.
 */
class RelayNetworkAccessManager : public QNetworkAccessManager {
    Q_OBJECT

   public:
    static constexpr const char* TOKEN_HEADER = "X-Relay-Token";

    explicit RelayNetworkAccessManager(QObject* parent = nullptr);

    /**
     * Set the relay. An empty relayUrl turns the relay off (the manager then behaves like a plain QNetworkAccessManager).
     * Anything else must be an http:// or https:// URL and needs a token; otherwise the manager enters its fail-closed
     * state. Plain http:// works for any address but sends the token and the sign-in tokens unencrypted (a warning is logged).
     */
    void configure(const QString& relayUrl, const QString& token);

    /** True when a relay was requested, even if the configuration turned out to be unusable. */
    bool routesThroughRelay() const { return m_mode != Mode::Direct; }
    /** True when the relay configuration is usable. */
    bool relayReady() const { return m_mode == Mode::Relay; }

    /**
     * Compute the relay URL for a request URL.
     * Returns an empty URL when the request must not be relayed: non-http(s) schemes, loopback hosts, and the relay itself.
     * Plain http URLs are relayed as https; the relay always talks https to the upstream host.
     */
    static QUrl rewriteForRelay(const QUrl& original, const QUrl& relayBase);

   protected:
    QNetworkReply* createRequest(Operation op, const QNetworkRequest& request, QIODevice* outgoingData = nullptr) override;

   private:
    enum class Mode { Direct, Relay, FailClosed };

    Mode m_mode = Mode::Direct;
    QUrl m_relayBase;
    QByteArray m_token;
};
