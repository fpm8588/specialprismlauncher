# prism-relay

A small relay server for this Prism Launcher fork. Run it on a computer that can reach
Mojang, Microsoft and the other services Prism uses (for example your home PC). The launcher
then sends **every request to the relay** instead of contacting those services itself.

```
Prism (this device)            your home PC                      the internet
        │  https://home.example.com/r/libraries.minecraft.net/…
        ├─────────────────────────────▶ checks token + allowlist
        │                              ├─────────────────────────▶ libraries.minecraft.net
        │◀─────────────────────────────┤◀────────────────────────┘
        │   response streamed back
```

The only host this device talks to is the relay. Redirects (GitHub releases, CDNs…) are
followed by the relay, so the launcher never sees them.

> Using this to get around a network's filter can break that network's acceptable-use rules.
> That is your call to make; the relay does nothing to disguise its traffic.

## 1. Run the relay on the home computer

Build (needs Go 1.26+), or cross-compile for another OS:

```sh
cd relay
go build -o prism-relay .
# for another machine, e.g. Windows:  GOOS=windows GOARCH=amd64 go build -o prism-relay.exe .
```

Make a token. This is the shared secret between the launcher and the relay:

```sh
./prism-relay -gen-token > relay-token.txt
```

### Option A: automatic HTTPS certificate (recommended)

You need a DNS name pointing at your home connection (a dynamic-DNS name is fine, e.g. from
DuckDNS or your router vendor) and **only port 443** forwarded to this computer.

```sh
./prism-relay -domain relay.example.com -token-file relay-token.txt
```

It gets and renews a Let's Encrypt certificate by itself (stored in `./certs`). Binding
port 443 needs root on Linux (`sudo setcap 'cap_net_bind_service=+ep' ./prism-relay`
lets a normal user do it) and an administrator prompt on Windows the first time.

### Option B: you already have a certificate

```sh
./prism-relay -cert fullchain.pem -key privkey.pem -listen :8443 -token-file relay-token.txt
```

Forward whatever port you chose.

### Option C: behind Caddy / nginx

```sh
./prism-relay -plain-http -listen 127.0.0.1:8080 -token-file relay-token.txt
```

and have the reverse proxy terminate TLS. Do not expose `-plain-http` to the internet
directly: the token would travel unencrypted.

### Router and firewall

1. Give the home computer a fixed LAN address.
2. Forward the TCP port from step A/B to it.
3. Allow that port in the computer's firewall.

### Check that it works

From any other machine:

```sh
curl -H "X-Relay-Token: $(cat relay-token.txt)" https://relay.example.com/healthz     # ok
curl -H "X-Relay-Token: $(cat relay-token.txt)" -I https://relay.example.com/r/libraries.minecraft.net/
```

## 2. Point the launcher at it

Either in the launcher: **Settings → APIs → Relay Server**, enter `https://relay.example.com`
and the token. Or without touching settings, using environment variables (these win over the
settings):

```sh
PRISM_RELAY_URL=https://relay.example.com PRISM_RELAY_TOKEN=… ./PrismLauncher
```

Leave the URL empty to go back to connecting directly.

If a relay is set but the URL or token is unusable, requests **fail** (they target a name
that cannot resolve) instead of quietly going out directly.

## What goes through the relay, and what does not

Through the relay: everything the launcher itself downloads or asks for: sign-in (device
code), Xbox and Minecraft services, version metadata, libraries, assets, the Java runtime,
mod loaders, CurseForge and Modrinth, GitHub, Prism's own servers. At launch the
"resolve Mojang servers" diagnostics step is skipped in relay mode so the device does not
look those names up either.

**Not** through the relay:

* **The game itself.** Minecraft is a separate Java process; its own traffic (joining an
  online server calls `sessionserver.mojang.com`, skins, realms…) does not use the launcher's
  network stack.
* **Your web browser.** The device-code sign-in asks you to enter a code at
  `microsoft.com/link`. Do that on another device (a phone is fine) if the network blocks it.
* **Pinging Minecraft servers** from the instance's server list, which are direct game-server
  connections.
* The separate `prism-updater` helper, if you build it.

## The allowlist

The relay only forwards to hosts on its allowlist, so a leaked token cannot turn your home
connection into a general proxy. `./prism-relay -print-allowlist` shows the built-in list.
If the launcher hits a host that is not on it, the relay answers **403** and says which
host; the launcher log shows that text. Add it:

```sh
./prism-relay … -allow cdn.example.org,*.example.net
./prism-relay … -allow-file extra-hosts.txt        # one host per line, # comments
```

`*.example.net` matches subdomains, not `example.net` itself. Only the default HTTPS port is
allowed unless an entry names the port (`example.org:8443`).

## Security notes

* The token is the only credential. Treat it like a password; generate a new one with
  `-gen-token` and restart the relay if you think it leaked. In the launcher it is stored in
  plain text in `prism.cfg`, like the CurseForge and Modrinth keys.
* After 10 wrong tokens an address is locked out for 15 minutes.
* The relay refuses to connect to private, loopback and link-local addresses, so an allowed
  name that resolves to your home network is not reachable through it.
* Logs contain method, host, path and status, not query strings or headers. The relay does
  see your Microsoft and Minecraft access tokens in transit, since it makes those requests
  for you: only run it on a machine and connection you control.

## Tests

```sh
go test -race ./...
```
