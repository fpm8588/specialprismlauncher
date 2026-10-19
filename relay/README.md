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
3. **Server tab:** type your domain name and press Save. Forward TCP port 443 on your router to
   this computer (the tab shows the address to use).
4. Press **Start relay**. Windows Firewall will ask to allow access: choose **Allow**.
5. **Server tab → Check certificate** proves the internet can reach you and fetches the free
   Let's Encrypt certificate.
6. **Connect tab:** copy the address and token into the launcher (*Settings → APIs → Relay Server*).

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
