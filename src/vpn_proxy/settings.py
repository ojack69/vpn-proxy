"""Settings: defaults, optional TOML overrides and host-side detection."""

from __future__ import annotations

import getpass
import ipaddress
import json
import os
import platform
import socket
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path

import psutil

CONFIG_DIR_NAME = ".wg-proxy-vpn"
SETTINGS_FILE_NAME = "settings.toml"


@dataclass(frozen=True)
class User:
    name: str
    home: Path
    uid: int
    gid: int


# PUID/PGID for the linuxserver image when the host has no POSIX ids (Windows)
DEFAULT_ID = 1000


def current_user() -> User:
    """The invoking user, resolving through sudo so the config lands in their home."""
    if sys.platform == "win32":
        return User(name=getpass.getuser(), home=Path.home(), uid=DEFAULT_ID, gid=DEFAULT_ID)
    import pwd

    name = os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name
    entry = pwd.getpwnam(name)
    return User(name=entry.pw_name, home=Path(entry.pw_dir), uid=entry.pw_uid, gid=entry.pw_gid)


REDIRECT_MODES = ("loopback", "bridge", "custom")
FORWARDER_IMAGE = "alpine/socat:latest"


@dataclass(frozen=True)
class ForwarderSpec:
    image: str
    command: list[str]
    host_network: bool  # Linux: runs in the host netns to reach the host's loopback


@dataclass
class Settings:
    vpn_subnet: str = "10.80.80.0"
    vpn_udp_port: int = 51820
    vpn_peer_dns: str = "1.1.1.1"
    redirected_tcp_ports: str = "80,443"
    # Host interface used to derive the WireGuard endpoint; None = default-route interface
    interface: str | None = None
    # Where redirected traffic goes:
    #   loopback: proxy on the host's 127.0.0.1:local_port, reached through a socat forwarder
    #   bridge:   proxy bound to the docker bridge gateway (or 0.0.0.0) on local_port, Linux only
    #   custom:   proxy at proxy_host:local_port (e.g. another machine on the LAN)
    redirect: str = "loopback"
    # Port the intercepting proxy (Burp/mitmproxy) listens on
    local_port: int = 8080
    proxy_host: str | None = None
    # Port of the socat forwarder container (non-Linux loopback mode only)
    relay_port: int = 8080
    container_name: str = "wg-proxy-vpn-server"
    docker_subnet: str = "172.31.80.0/24"
    user: User = field(default_factory=current_user)

    def __post_init__(self) -> None:
        if isinstance(self.redirected_tcp_ports, (list, tuple)):
            self.redirected_tcp_ports = ",".join(str(p) for p in self.redirected_tcp_ports)
        self.redirected_tcp_ports = normalize_ports(self.redirected_tcp_ports)
        ipaddress.ip_network(self.docker_subnet)  # fail early on a malformed subnet
        if self.redirect not in REDIRECT_MODES:
            raise ValueError(f"redirect must be one of {', '.join(REDIRECT_MODES)}")
        if self.redirect == "custom" and not self.proxy_host:
            raise ValueError("redirect = custom requires proxy_host")
        if self.redirect == "bridge" and not is_linux():
            raise ValueError("redirect = bridge only works on Linux (Docker runs in a VM elsewhere)")

    # --- paths -----------------------------------------------------------------

    @property
    def config_path(self) -> Path:
        return self.user.home / CONFIG_DIR_NAME

    @property
    def settings_path(self) -> Path:
        return self.config_path / SETTINGS_FILE_NAME

    @property
    def wg_config_path(self) -> Path:
        """Mounted as /config in the wireguard container."""
        return self.config_path / "config"

    @property
    def peer_config_path(self) -> Path:
        return self.wg_config_path / "peer1" / "peer1.conf"

    # --- docker names / addressing --------------------------------------------

    @property
    def forwarder_name(self) -> str:
        return f"{self.container_name}-forwarder"

    @property
    def legacy_mitmproxy_name(self) -> str:
        """Relay container created by the old bash script."""
        return f"{self.container_name}-mitmproxy"

    @property
    def network_name(self) -> str:
        return f"{self.container_name}-net"

    def _subnet_host(self, index: int) -> str:
        return str(ipaddress.ip_network(self.docker_subnet)[index])

    @property
    def gateway_ip(self) -> str:
        return self._subnet_host(1)

    @property
    def wireguard_ip(self) -> str:
        return self._subnet_host(2)

    @property
    def forwarder_ip(self) -> str:
        return self._subnet_host(3)

    # --- redirect --------------------------------------------------------------

    @property
    def dnat_target(self) -> tuple[str, int]:
        if self.redirect == "custom":
            return self.proxy_host, self.local_port
        if self.redirect == "loopback" and not is_linux():
            return self.forwarder_ip, self.relay_port
        # bridge, and loopback on Linux (forwarder listens on the gateway IP)
        return self.gateway_ip, self.local_port

    @property
    def proxy_check_target(self) -> tuple[str, int]:
        """Where the proxy itself should be listening, as seen from the host."""
        if self.redirect == "custom":
            return self.proxy_host, self.local_port
        if self.redirect == "bridge":
            return self.gateway_ip, self.local_port
        return "127.0.0.1", self.local_port

    def forwarder_spec(self) -> ForwarderSpec | None:
        if self.redirect != "loopback":
            return None
        if is_linux():
            # Host netns: bound to the bridge IP only, accepting only the WireGuard container
            # (source after its MASQUERADE -o eth+), so nothing is exposed on the LAN.
            listen = (
                f"TCP-LISTEN:{self.local_port},bind={self.gateway_ip},"
                f"range={self.wireguard_ip}/32,fork,reuseaddr"
            )
            return ForwarderSpec(
                FORWARDER_IMAGE, [listen, f"TCP:127.0.0.1:{self.local_port}"], host_network=True
            )
        return ForwarderSpec(
            FORWARDER_IMAGE,
            [
                f"TCP-LISTEN:{self.relay_port},fork,reuseaddr",
                f"TCP:host.docker.internal:{self.local_port}",
            ],
            host_network=False,
        )


def _port(value: str) -> int:
    n = int(value)
    if not 1 <= n <= 65535:
        raise ValueError(f"port out of range (1-65535): {value}")
    return n


def normalize_ports(spec: str) -> str:
    """Validate a comma-separated iptables multiport `--dports` spec and canonicalize it.

    Accepts single ports (`80`) and ranges (`8000:8100`); strips whitespace and
    rejects empty or malformed entries. iptables multiport allows at most 15 ports,
    counting each range endpoint, so enforce that too."""
    entries = [e.strip() for e in str(spec).split(",") if e.strip()]
    if not entries:
        raise ValueError("redirected_tcp_ports must list at least one port")
    count = 0
    out = []
    for e in entries:
        if ":" in e:
            lo, hi, *rest = e.split(":")
            if rest or _port(lo) > _port(hi):
                raise ValueError(f"invalid port range: {e}")
            out.append(f"{_port(lo)}:{_port(hi)}")
            count += 2
        else:
            out.append(str(_port(e)))
            count += 1
    if count > 15:
        raise ValueError("iptables multiport allows at most 15 ports (ranges count as 2)")
    return ",".join(out)


def is_linux() -> bool:
    return platform.system() == "Linux"


def default_path() -> Path:
    return current_user().home / CONFIG_DIR_NAME / SETTINGS_FILE_NAME


def _read(path: Path) -> dict:
    if not path.is_file():
        return {}
    with path.open("rb") as fh:
        return tomllib.load(fh)


def load(path: Path | None = None, **overrides) -> Settings:
    """Defaults < TOML file < `overrides` (e.g. CLI flags; None values are ignored)."""
    path = path or default_path()
    values = _read(path) | {k: v for k, v in overrides.items() if v is not None}
    allowed = {f.name for f in fields(Settings)} - {"user"}
    unknown = set(values) - allowed
    if unknown:
        raise ValueError(f"Unknown setting(s) in {path}: {', '.join(sorted(unknown))}")
    return Settings(user=current_user(), **values)


def _toml_value(v: object) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v)  # JSON string escaping is valid TOML basic-string syntax
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    raise TypeError(f"unsupported TOML value: {v!r}")


def save_overrides(path: Path, **values) -> None:
    """Merge `values` into the TOML file; a None value removes the key."""
    data = _read(path)
    for k, v in values.items():
        if v is None:
            data.pop(k, None)
        else:
            data[k] = v
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(f"{k} = {_toml_value(v)}\n" for k, v in data.items()), encoding="utf-8"
    )


def detect_host_ip(interface: str | None = None) -> str | None:
    """IPv4 address the VPN client should connect to."""
    if interface:
        for addr in psutil.net_if_addrs().get(interface, []):
            if addr.family == socket.AF_INET:
                return addr.address
        return None

    if platform.system() == "Linux":
        try:
            out = subprocess.run(
                ["ip", "-j", "route", "get", "1.1.1.1"], capture_output=True, text=True, check=True
            ).stdout
            src = json.loads(out)[0].get("prefsrc")
            if src:
                return src
        except (OSError, subprocess.CalledProcessError, ValueError, IndexError):
            pass

    # Portable fallback: a connected UDP socket picks the default-route source address
    # without sending anything.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("1.1.1.1", 53))
            return s.getsockname()[0]
    except OSError:
        return None
