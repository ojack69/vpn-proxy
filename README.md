# wg-proxy-vpn

A TUI/CLI tool that spins up a WireGuard VPN server in Docker and transparently redirects HTTP/HTTPS traffic from connected clients to a proxy of your choice (e.g. Burp Suite, mitmproxy). It's designed for **mobile application security assessments** — particularly Flutter apps — where traffic interception via standard system-proxy configuration is unreliable or ignored by the app.

> Based on: [Intercepting Flutter traffic on iOS — NVISO Labs](https://blog.nviso.eu/2020/06/12/intercepting-flutter-traffic-on-ios/)

---

## Why this exists

Many mobile frameworks (Flutter being the classic example) don't respect the device's configured HTTP proxy — they open sockets directly. Instead of relying on the app to *use* a proxy, all its traffic is forced through a VPN tunnel and TCP traffic on ports 80/443 is DNAT'ed to your proxy at the network level.

## How it works

1. A dedicated Docker network (`wg-proxy-vpn-server-net`, default `172.31.80.0/24`) is created; containers get static IPs on it.
2. A [linuxserver/wireguard](https://docs.linuxserver.io/images/docker-wireguard/) container is created with a single peer.
3. The redirect rule is written as **wg-quick `PostUp`/`PostDown` hooks** into the server config (`templates/server.conf` and `wg_confs/wg0.conf`):
   ```
   iptables -t nat -A PREROUTING -i wg0 -p tcp -m multiport --dports 80,443 -j DNAT --to-destination <target>
   ```
   wg-quick re-applies it every time `wg0` comes up, so the redirect survives `docker restart`, daemon restarts and container crashes — not only restarts done through this tool. Return traffic is handled by the image's own `MASQUERADE -o eth+` hook.
4. The redirect target is selectable (`redirect` setting, `start --redirect`, or `t` in the TUI):

| mode | your proxy listens on | how traffic gets there |
|---|---|---|
| `loopback` (default) | `127.0.0.1:<local_port>`, Burp's default | Linux: a `socat` forwarder in the host network namespace, bound **only** to the docker bridge IP (`172.31.80.1`) and accepting **only** the WireGuard container, relays to `127.0.0.1`. macOS/Windows: a `socat` container (`172.31.80.3:<relay_port>`) relays to `host.docker.internal:<local_port>`. |
| `bridge` (Linux only) | `172.31.80.1` or `0.0.0.0` | DNAT straight to the bridge gateway, no forwarder |
| `custom` | `<proxy_host>:<local_port>`, e.g. Burp on another machine | DNAT straight to that address, no forwarder |

The forwarder is a plain TCP relay, not a proxy. Your proxy still sees the client's original TLS SNI/Host header, so invisible proxying works, and there is no second TLS interception.

```
loopback:        client → WireGuard (DNAT) → socat forwarder → 127.0.0.1:8080 (Burp)
bridge / custom: client → WireGuard (DNAT) → proxy
```

Only the client endpoint (`SERVERURL`) depends on your LAN IP. If it changes, the tool flags the endpoint as stale and you can recreate the container. Keys are kept, and the peer config is re-rendered.

---

## Prerequisites

- **Docker** running, and access to its socket (`docker` group or sudo).
- [uv](https://docs.astral.sh/uv/).
- An intercepting proxy with **invisible/transparent proxying** enabled. With the default `loopback` mode it can stay on `127.0.0.1:8080`.
- A WireGuard client on the test device.

## Install / run

```bash
uv run vpn-proxy              # TUI
uv run vpn-proxy start        # or any subcommand
uv tool install .             # optional: puts `vpn-proxy` on PATH
```

## Configuration

Optional, in `~/.wg-proxy-vpn/settings.toml` (with sudo, `~` is `$SUDO_USER`'s home). All keys are optional:

```toml
vpn_subnet = "10.80.80.0"         # WireGuard tunnel subnet
vpn_udp_port = 51820              # UDP port exposed on the host
vpn_peer_dns = "1.1.1.1"          # DNS pushed to the client
redirected_tcp_ports = [80, 443]  # or "80,443"
interface = "wlp1s0"              # endpoint interface; default: default-route interface
redirect = "loopback"             # loopback | bridge | custom (see above)
local_port = 8080                 # port your proxy (Burp/mitmproxy) listens on
proxy_host = "192.168.1.50"       # proxy address, redirect = custom only
relay_port = 8080                 # socat container port (non-Linux loopback only)
container_name = "wg-proxy-vpn-server"
docker_subnet = "172.31.80.0/24"  # gateway .1, wireguard .2, forwarder .3
```

Keys, peer configs and server config live in `~/.wg-proxy-vpn/config` (mounted as `/config`).

---

## Usage

### TUI

`uv run vpn-proxy` shows live:

- **Server**: container state, host IP, client endpoint, legacy/stale-endpoint warnings.
- **Peer**: last handshake, client source address, rx/tx.
- **Redirect**: mode, DNAT target, whether the rule is present and its packet/byte counters (proof traffic is actually being redirected), whether your proxy is listening, and whether the WireGuard container can actually reach it (`nc -z` from inside, i.e. the full path including the forwarder and the host firewall).
- **Log**: actions and Docker events. After any start of the WireGuard container, including one done outside the tool, it checks that the redirect rule is back.

Keys: `s` start · `x` stop · `c` client config + QR · `t` redirect target · `r` recreate · `u` uninstall · `q` quit.

### CLI

```bash
vpn-proxy start [--recreate] [--redirect loopback|bridge|custom] [--proxy-host H] [--local-port P]
                               # create/start, apply redirect hook, print client config + QR
                               # redirect flags are saved to settings.toml
vpn-proxy stop
vpn-proxy config               # client config (ListenPort stripped) + QR code
vpn-proxy status
vpn-proxy uninstall [-y]       # remove containers, network, keys and config (irreversible)
```

**Typical workflow:**

1. Start Burp on `127.0.0.1:8080` (the default) with invisible proxying.
2. `vpn-proxy start`, then scan the QR code with the WireGuard app.
3. Install/trust the proxy CA on the device (pinning bypass is out of scope).
4. Use the app; the TUI's DNAT counter should increase and traffic should appear in Burp.

### Migrating from the bash script

Containers created by the old `vpn-proxy.sh` (default bridge, no labels, plus the `-mitmproxy` relay) are detected as legacy. Run `vpn-proxy start --recreate` (or `r` in the TUI): the containers are replaced, and `~/.wg-proxy-vpn` (keys, peer) is reused.

---

## Notes

- **Certificate pinning is out of scope**: this handles routing only.
- **Only `redirected_tcp_ports` are redirected**. Everything else goes through the VPN untouched (`ALLOWEDIPS=0.0.0.0/0`).
- **Host firewall (Linux, `loopback`/`bridge`)**: traffic enters the host on the `wg-proxy-vpn-server-net` bridge towards `172.31.80.1:<local_port>`, so the firewall must allow it. The TUI's "VPN → proxy" line shows `blocked` when it doesn't.
- **macOS/Windows `loopback`** relies on Docker Desktop's `host.docker.internal` reaching services bound to the host's loopback. If it doesn't in your setup, use `custom` with the host's LAN IP.
- Use only in **controlled assessment environments**: an exposed WireGuard server NAT'ing HTTP/HTTPS has real security implications if left running.
