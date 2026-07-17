# wg-proxy-vpn

A bash script that spins up a WireGuard VPN server in Docker and transparently redirects HTTP/HTTPS traffic from connected clients to a proxy of your choice (e.g. Burp Suite, mitmproxy). It's designed for **mobile application security assessments** — particularly Flutter apps — where traffic interception via standard system-proxy configuration is unreliable or ignored by the app.

> Based on: [Intercepting Flutter traffic on iOS — NVISO Labs](https://blog.nviso.eu/2020/06/12/intercepting-flutter-traffic-on-ios/)

---

## Why this exists

Many mobile frameworks (Flutter being the classic example) don't respect the device's configured HTTP proxy — they open sockets directly, bypassing whatever proxy settings you've set on the OS or Wi-Fi network. That makes traditional "set a proxy on the device" interception useless.

The workaround: instead of relying on the app to *use* a proxy, force **all** its outbound traffic through a VPN tunnel, then transparently redirect TCP traffic on ports 80/443 to your proxy at the network level (via `iptables` DNAT), regardless of whether the app knows a proxy exists.

## How it works

1. A [linuxserver/wireguard](https://docs.linuxserver.io/images/docker-wireguard/) container is created and configured as a WireGuard VPN server with a single peer.
2. Your mobile device connects to this VPN using the generated peer configuration.
3. `iptables` rules inside the container's network namespace:
   - `DNAT` traffic on the configured TCP ports (default `80,443`) arriving on the `wg0` interface to your host proxy (`LOCAL_HOST:LOCAL_PORT`).
   - Allow that forwarded traffic through `FORWARD`.
   - `MASQUERADE` return traffic so replies find their way back to the client.
4. Your proxy tool (Burp, mitmproxy, etc.), listening on the host, sees and can intercept/modify all HTTP/HTTPS traffic from the device — even though the app never explicitly configured a proxy.

### macOS / Windows caveat

On non-Linux hosts, Docker runs inside a lightweight VM, so `iptables`-based routing to a proxy "on the host" doesn't behave the same way as on native Linux. To work around this, the script detects a non-Linux host OS and automatically spins up an **additional `mitmproxy` container** running in **upstream mode**, configured to forward everything to your host proxy (`http://LOCAL_HOST:LOCAL_PORT`). Traffic then flows:

```
Mobile client → WireGuard container (iptables DNAT) → mitmproxy container (upstream mode) → Host proxy (Burp/mitmproxy/etc.)
```

On Linux, this extra hop is skipped entirely — traffic is DNAT'ed directly to the host proxy.

---

## Prerequisites

- **Docker** installed and running (the script checks for both and exits if either is missing).
- Root/sudo privileges are recommended (needed at least for `uninstall`, and generally for Docker + `NET_ADMIN`/`SYS_MODULE` capabilities).
- A proxy tool already listening on the host at the configured `LOCAL_PORT` (default `8080`) — e.g. Burp Suite or mitmproxy — with **invisible/transparent proxying enabled**, since the client won't be sending standard proxy CONNECT requests.
- A WireGuard client on the test device (mobile app, or `wg-quick` on desktop).
- *(Optional)* `qrencode` installed on the host if you want the peer config rendered as a scannable QR code (handy for quickly importing onto a phone).

---

## Configuration

Before running, review and adjust the variables at the top of the script to match your environment:

| Variable | Default | Description |
|---|---|---|
| `VPN_SUBNET` | `10.80.80.0` | Internal subnet used for the VPN tunnel |
| `VPN_UDP_PORT` | `51820` | UDP port WireGuard listens on (exposed on the host) |
| `VPN_PEER_DNS` | `1.1.1.1` | DNS server pushed to VPN clients |
| `REDIRECTED_TCP_PORTS` | `80,443` | TCP ports redirected to the proxy (comma-separated, used with `iptables --multiport`) |
| `LOCAL_INTERFACE` | `wlp1s0` | **Must be changed** to match your host's active network interface (used to auto-detect `LOCAL_HOST` via `ifconfig`) |
| `PROXY_PORT` | `8080` | Port used by the intermediate mitmproxy container (non-Linux hosts only) |
| `LOCAL_PORT` | `8080` | Port your actual proxy tool (Burp/mitmproxy) is listening on, on the host |
| `CONTAINER_NAME` | `wg-proxy-vpn-server` | Name of the WireGuard Docker container |

`LOCAL_HOST` is auto-detected from `LOCAL_INTERFACE` via `ifconfig`; double-check it resolves correctly on your system (in particular, confirm `wlp1s0` matches your machine's actual interface name — use `ip a` or `ifconfig` to check).

Peer configuration files, keys, and logs are persisted under:

```
/home/<user>/.wg-proxy-vpn
```

(`<user>` resolves to `$SUDO_USER` if run with `sudo`, otherwise `$USER`.)

---

## Usage

```bash
./vpn-proxy.sh [start|stop|config|uninstall]
```

### `start`

- If the WireGuard container doesn't exist yet, creates it:
  - Creates the config directory (`~/.wg-proxy-vpn`).
  - On non-Linux hosts, also creates and starts a `mitmproxy` container in upstream mode pointing at your host proxy.
  - Runs the `linuxserver/wireguard` container with `NET_ADMIN`/`SYS_MODULE` capabilities, one peer, and the settings above.
  - Waits a few seconds for the server to initialize, then prints the generated peer config (see `config` below).
- Starts (or re-starts) the WireGuard container (and the mitmproxy container, if present).
- (Re-)applies the `iptables` DNAT/FORWARD/MASQUERADE rules described above.
- Prints a reminder about the expected host/port and to enable invisible/transparent proxying in your proxy tool.

**Typical workflow:**

1. Start your proxy (e.g. Burp Suite) listening on `LOCAL_PORT`, with invisible proxying enabled.
2. Run `./vpn-proxy.sh start`.
3. Import the printed/QR peer config into the WireGuard app on your test device.
4. Connect the device to the VPN.
5. Install/trust your proxy's CA certificate on the test device (still required for HTTPS interception — this script only handles traffic *routing*, not certificate trust or pinning bypass).
6. Use the target app; its HTTP/HTTPS traffic on the redirected ports should now appear in your proxy.

### `stop`

Stops the WireGuard container and the mitmproxy container (if it exists), without deleting any configuration.

### `config`

Prints the existing peer configuration file (`peer1.conf`) with the `ListenPort` line stripped out, plus a QR code rendering of it if `qrencode` is installed. Useful if you need to re-import the config on another device without recreating the server. Fails with an error if the server hasn't been set up yet.

### `uninstall`

- Prompts for confirmation (`y/N`).
- **Requires root** (exits if `$EUID -ne 0`).
- Deletes the entire `~/.wg-proxy-vpn` config directory.
- Stops and removes both the WireGuard container and the mitmproxy container.

This is destructive and irreversible — all peer keys and configuration are lost.

---

## Notes, caveats & troubleshooting

- **Certificate pinning is out of scope.** This script solves traffic *routing/redirection*, not certificate trust. Apps with certificate pinning will still need a separate bypass (e.g. Frida scripts, patched binaries) in addition to this setup.
- **Only TCP ports listed in `REDIRECTED_TCP_PORTS` are redirected.** Traffic on other ports/protocols passes through the VPN normally (subject to `ALLOWEDIPS=0.0.0.0/0`) but isn't touched by the proxy redirection rules.
- **`LOCAL_INTERFACE` must be correct**, or `LOCAL_HOST` will resolve to nothing/incorrect data and the whole redirection chain breaks. Verify with `ip a` / `ifconfig` before running.
- **Re-running `start`** re-applies the `iptables` rules each time (they are appended, not replaced) — if you restart the script repeatedly without a `stop`/container recreation, you may end up with duplicate NAT rules. If you suspect this, `stop` and recreate the container, or clear the rules manually with `docker exec <container> iptables -t nat -F`.
- **Docker must already be running** before invoking the script; the script exits early with an error if `docker ps` fails or `docker` isn't found.
- **Enable "invisible" / transparent proxying** in your interception proxy (e.g. Burp Suite's "Support invisible proxying" option) — since clients are being transparently redirected rather than explicitly configured to use a proxy, they won't send proxy-style requests (e.g. absolute-form HTTP requests or CONNECT).
- Intended for use in **controlled security assessment environments** — exposing a WireGuard server with `ALLOWEDIPS=0.0.0.0/0` and NAT'ing all HTTP/HTTPS traffic through it has real security implications if left running outside that context.

---

## Requirements summary

- Docker
- WireGuard client on the test device
- A host-based intercepting proxy (Burp Suite, mitmproxy, etc.)
- `qrencode` (optional, for QR-based config import)
- Linux host recommended for the simplest routing path; macOS/Windows supported via an automatic mitmproxy relay
