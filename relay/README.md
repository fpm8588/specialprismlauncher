# prism-relay

The home-computer half of this Prism Launcher fork. It is a single program with a built-in admin
page. Run it on a computer that can reach Mojang, Microsoft and the other services Prism uses; the
launcher then sends **every request to the relay** instead of contacting those services itself.

```
Prism (the Mac)                  your home PC                         the internet
   │  https://relay.example.com/r/libraries.minecraft.net/…
   ├──────────────────────────────▶ checks token + allowlist
   │                               ├──────────────────────────────▶ libraries.minecraft.net
   │◀──────────────────────────────┤◀─────────────────────────────┘
   │   response streamed back
```

Redirects (GitHub releases, CDNs…) are followed by the relay, so the launcher never sees them.

## Joining online servers (the game's login)

The game itself, not the launcher, makes one web request when you join an online server: the "join"
call to Mojang's session server. If the network blocks it, the game says *Authentication servers
are down*. The launcher handles this with a small proxy on the Mac (127.0.0.1 only) that the game is
told to use for its web requests (`--proxyHost`/`--proxyPort`). The proxy asks the relay for a
`CONNECT host:443` tunnel, and the relay opens it only for hosts on the allowlist, on port 443 (other
ports need an explicit `host:port` entry), each tunnel capped at 16 MiB per direction and 5 minutes.

The connection to the Minecraft server itself is a plain socket the proxy never sees, so no game
traffic reaches your home connection. The Activity tab shows these as `CONNECT … (game login tunnel)`.
The launcher setting *Also send the game's login through the relay* turns this off.

> Using this to get around a network's filter can break that network's acceptable-use rules.
> That is your call to make; the relay does nothing to disguise its traffic.

The full walkthrough, with troubleshooting, is in the project document "Prism Home Relay: How
Everything Works". This file is the short version.

## Windows 10 quick start

1. Copy `prism-relay.exe` somewhere permanent (for example `C:\PrismRelay\`) and double-click it.
   Windows SmartScreen may say "Windows protected your PC" because the file is not code-signed:
   choose **More info → Run anyway**.
2. A console window opens and your browser opens the **admin page**. Keep the console open (closing
   it stops the relay), or turn on *Tools → Start when I sign in* to run it hidden in the background.
3. **Server tab:** type your domain name and press Save. Forward TCP ports **443 and 80** on your
   router to this computer (the tab shows the address to use). Let's Encrypt uses port 80 to check
   that you own the domain; the relay answers it there and sends everything else to https.
4. Press **Start relay**. Windows Firewall will ask to allow access: choose **Allow**.
5. **Server tab → Check certificate** proves the internet can reach you and fetches the free
   Let's Encrypt certificate.
6. **Connect tab:** copy the address and token into the launcher (*Settings → APIs → Relay Server*).

## Running on Linux (Ubuntu server)

`prism-relay-linux-amd64` is the same program. It has no window, so it runs as a service, and its
admin page is opened from another computer on your network.

```
sudo useradd --system --home /var/lib/prism-relay --shell /usr/sbin/nologin prismrelay
sudo mkdir -p /opt/prism-relay /var/lib/prism-relay
sudo install -m 755 prism-relay-linux-amd64 /opt/prism-relay/prism-relay
sudo install -m 644 prism-relay.service /etc/systemd/system/prism-relay.service   # from relay/deploy/
sudo chown -R prismrelay:prismrelay /var/lib/prism-relay
sudo systemctl daemon-reload && sudo systemctl enable --now prism-relay
sudo journalctl -u prism-relay -n 20 --no-pager      # shows the admin sign-in link
```

* **The admin page** listens where `-admin-addr` says (the service file uses `192.168.0.127:9777`;
  change it to the server's own address). Only loopback and private addresses (`192.168.x.x`,
  `10.x.x.x`, `172.16-31.x.x`) are accepted, and a connection from the internet is refused even if
  the router forwards the port, so **never forward the admin port**. Open the sign-in link from the
  journal in a browser on the home network; it is plain http, so use it on your own network only.
* **Moving from Windows:** stop the relay there, copy the whole `%AppData%\PrismRelay` folder into
  `/var/lib/prism-relay` (same token, allowlist and certificate, so nothing is re-issued), then
  `chown -R prismrelay:prismrelay /var/lib/prism-relay` and start the service.
* **Firewall:** open the relay's ports, for example
  `sudo firewall-cmd --permanent --add-port=443/tcp --add-port=80/tcp`, and the admin port for the
  home network only:
  `sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.0.0/24" port port="9777" protocol="tcp" accept'`,
  then `sudo firewall-cmd --reload`.
* If something else on the server already uses port 80 or 443, set the relay's listen address on the
  Server tab (for example `:8443`) and point the router's external 443 at that port.

## The admin page

It is served only on `127.0.0.1:9777` and needs a secret key, so only a browser started by the
program can open it. Run the program again at any time to get back to it.

| Tab | What it is for |
| --- | --- |
| Overview | Setup checklist, request counters, busiest hosts |
| Connect | The address and token for the launcher, a copy-paste Terminal command for the Mac, new token |
| Server | Domain, certificate mode (automatic / own files / none), port, certificate check, router instructions |
| Allowed hosts | Blocked requests with one-click Allow, add or remove hosts, "would this URL be allowed?", the built-in list |
| Activity | Live log of every request, filter, problems only |
| Tools | Self-test of every service Prism needs, start with Windows, firewall rule, data folder, quit |

## Files

Settings, certificates and the log live in `%APPDATA%\PrismRelay\` (on Windows; `~/.config/PrismRelay`
on Linux, `~/Library/Application Support/PrismRelay` on macOS).

| File | Contents |
| --- | --- |
| `config.json` | All settings, including the token and the admin key. Keep it private. |
| `relay.log` | Every request (host, path, status, size; never query strings). Rolls over at 5 MB to `relay.log.1`. |
| `certs/` | Let's Encrypt account and certificates (`certs-staging/` in test mode) |

## Command line

```
prism-relay [-data-dir DIR] [-no-browser] [-background] [-version] [-gen-token] [-print-allowlist]
```

`-background` detaches from the console (used by *start with Windows*). `-no-browser` is for servers
without a screen: open the admin page through an SSH tunnel to port 9777. Everything else is set in
the admin page, or by editing `config.json` while the program is stopped.

## Build

Needs Go 1.26 or newer.

```sh
cd relay
go test -race ./...
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=1.0.0" -o prism-relay.exe .
```

Replace `GOOS`/`GOARCH` for other systems (`linux/amd64`, `darwin/arm64`, …). Built binaries are
written to `dist/`, which is not committed.

## Security notes

* The token is the only credential. Treat it like a password; make a new one on the Connect tab if
  you think it leaked. In the launcher it is stored in plain text in `prism.cfg`.
* The relay only forwards to hosts on its allowlist, so a leaked token cannot turn your home
  connection into a general proxy. It also refuses to connect to private, loopback and link-local
  addresses.
* After 10 wrong tokens an address is locked out for 15 minutes.
* The admin page checks a secret cookie, the `Host` header (against DNS rebinding), the `Origin` and
  a custom header on every change, so a web page you visit cannot drive it.
* The relay makes your Microsoft and Minecraft requests for you, so it sees those tokens in transit.
  Run it only on a machine and connection you control.
