"""Docker orchestration for the WireGuard server and the optional socat forwarder."""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass

import docker
from docker.errors import DockerException, ImageNotFound, NotFound
from docker.models.containers import Container

from . import wgconf
from .settings import Settings, detect_host_ip, is_linux

WIREGUARD_IMAGE = "lscr.io/linuxserver/wireguard:latest"
ROLE_LABEL = "vpn-proxy.role"
SPEC_LABEL = "vpn-proxy.spec"

Log = Callable[[str, str], None]  # (message, level: info|success|warning|error)


def _noop_log(message: str, level: str = "info") -> None:
    pass


class StackError(Exception):
    pass


class NeedsRecreate(StackError):
    """Existing container can't be reused as-is (legacy bash-created one)."""


@dataclass
class PeerInfo:
    public_key: str
    endpoint: str | None
    allowed_ips: str
    latest_handshake: int  # unix ts, 0 = never
    rx: int
    tx: int


@dataclass
class Status:
    wireguard: str  # missing | created | running | exited | ...
    forwarder: str | None  # None when the redirect mode doesn't use one
    redirect: str
    legacy: bool
    host_ip: str | None
    server_url: str | None
    target: tuple[str, int]

    @property
    def drift(self) -> bool:
        return bool(self.server_url and self.host_ip and self.server_url != self.host_ip)


class Stack:
    def __init__(self, settings: Settings, log: Log = _noop_log) -> None:
        self.s = settings
        self.log = log
        try:
            self.client = docker.from_env()
            self.client.ping()
        except DockerException as e:
            raise StackError(f"Docker is not reachable: {e}") from e

    # --- lookups ---------------------------------------------------------------

    def _get(self, name: str) -> Container | None:
        try:
            return self.client.containers.get(name)
        except NotFound:
            return None

    @property
    def wireguard(self) -> Container | None:
        return self._get(self.s.container_name)

    @property
    def forwarder(self) -> Container | None:
        return self._get(self.s.forwarder_name)

    def _is_legacy(self, wg: Container) -> bool:
        """WireGuard container created by the old bash script: no label, default bridge."""
        networks = wg.attrs["NetworkSettings"]["Networks"]
        return ROLE_LABEL not in wg.labels or self.s.network_name not in networks

    def _spec_hash(self) -> str | None:
        spec = self.s.forwarder_spec()
        if spec is None:
            return None
        raw = json.dumps([spec.image, spec.command, spec.host_network, self.s.forwarder_ip])
        return hashlib.sha1(raw.encode()).hexdigest()[:12]

    @staticmethod
    def _env(c: Container, key: str) -> str | None:
        for item in c.attrs["Config"].get("Env") or []:
            k, _, v = item.partition("=")
            if k == key:
                return v
        return None

    def status(self) -> Status:
        wg = self.wireguard
        fwd = self.forwarder
        return Status(
            wireguard=wg.status if wg else "missing",
            forwarder=(fwd.status if fwd else "missing") if self.s.forwarder_spec() else None,
            redirect=self.s.redirect,
            legacy=bool(wg and self._is_legacy(wg))
            or self._get(self.s.legacy_mitmproxy_name) is not None,
            host_ip=detect_host_ip(self.s.interface),
            server_url=self._env(wg, "SERVERURL") if wg else None,
            target=self.s.dnat_target,
        )

    # --- creation --------------------------------------------------------------

    def _create(self, image: str, **kwargs) -> Container:
        try:
            return self.client.containers.create(image, **kwargs)
        except ImageNotFound:
            self.log(f"Pulling {image}...", "info")
            self.client.images.pull(image)
            return self.client.containers.create(image, **kwargs)

    def _endpoint(self, ip: str) -> dict:
        return {self.s.network_name: self.client.api.create_endpoint_config(ipv4_address=ip)}

    def _network_exists(self) -> bool:
        try:
            self.client.networks.get(self.s.network_name)
            return True
        except NotFound:
            return False

    def ensure_network(self) -> None:
        if not self._network_exists():
            self.log(f"Creating docker network {self.s.network_name} ({self.s.docker_subnet})", "info")
            ipam = docker.types.IPAMConfig(
                pool_configs=[
                    docker.types.IPAMPool(subnet=self.s.docker_subnet, gateway=self.s.gateway_ip)
                ]
            )
            self.client.networks.create(
                self.s.network_name, driver="bridge", ipam=ipam, labels={ROLE_LABEL: "network"}
            )

    def _create_forwarder(self) -> Container:
        spec = self.s.forwarder_spec()
        assert spec is not None
        self.log(f"Creating forwarder: {' '.join(spec.command)}", "info")
        kwargs: dict = dict(
            command=spec.command,
            name=self.s.forwarder_name,
            detach=True,
            labels={ROLE_LABEL: "forwarder", SPEC_LABEL: self._spec_hash()},
        )
        if spec.host_network:
            kwargs["network_mode"] = "host"
        else:
            kwargs.update(
                extra_hosts={"host.docker.internal": "host-gateway"},
                network=self.s.network_name,
                networking_config=self._endpoint(self.s.forwarder_ip),
            )
        return self._create(spec.image, **kwargs)

    def _ensure_forwarder(self, recreate: bool) -> None:
        fwd = self.forwarder
        want = self._spec_hash()
        if fwd and (recreate or want is None or fwd.labels.get(SPEC_LABEL) != want):
            self._remove(fwd)
            fwd = None
        if want is None:
            return
        fwd = fwd or self._create_forwarder()
        if fwd.status != "running":
            fwd.start()

    def _create_wireguard(self, host_ip: str) -> Container:
        self.log(f"Creating WireGuard container (endpoint {host_ip}:{self.s.vpn_udp_port})", "info")
        self.s.wg_config_path.mkdir(parents=True, exist_ok=True)
        volumes = {str(self.s.wg_config_path): {"bind": "/config", "mode": "rw"}}
        if is_linux():
            # Docker Desktop (macOS/Windows) can't mount it and its kernel has WireGuard built in
            volumes["/lib/modules"] = {"bind": "/lib/modules", "mode": "ro"}
        return self._create(
            WIREGUARD_IMAGE,
            name=self.s.container_name,
            detach=True,
            labels={ROLE_LABEL: "wireguard"},
            cap_add=["NET_ADMIN", "SYS_MODULE"],
            environment={
                "PUID": str(self.s.user.uid),
                "PGID": str(self.s.user.gid),
                "TZ": "Etc/UTC",
                "SERVERURL": host_ip,
                "SERVERPORT": str(self.s.vpn_udp_port),
                "PEERS": "1",
                "PEERDNS": self.s.vpn_peer_dns,
                "PERSISTENTKEEPALIVE_PEERS": "25",
                "INTERNAL_SUBNET": self.s.vpn_subnet,
                "ALLOWEDIPS": "0.0.0.0/0",
                "LOG_CONFS": "true",
            },
            ports={"51820/udp": self.s.vpn_udp_port},
            volumes=volumes,
            sysctls={"net.ipv4.conf.all.src_valid_mark": "1"},
            network=self.s.network_name,
            networking_config=self._endpoint(self.s.wireguard_ip),
        )

    def _remove(self, c: Container | None) -> None:
        if c:
            self.log(f"Removing container {c.name}", "info")
            c.remove(force=True)

    # --- redirect hooks --------------------------------------------------------

    def _patch_confs(self) -> bool:
        host, port = self.s.dnat_target
        block = wgconf.render_block(self.s.redirected_tcp_ports, host, port)
        changed = False
        for path in (
            self.s.wg_config_path / "templates" / "server.conf",
            self.s.wg_config_path / "wg_confs" / "wg0.conf",
        ):
            if wgconf.patch_file(path, block):
                self.log(f"Redirect hook written to {path}", "info")
                changed = True
        return changed

    def _wait_for(self, predicate: Callable[[], bool], timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(1)
        return False

    # --- actions ---------------------------------------------------------------

    def start(self, recreate: bool = False) -> bool:
        host_ip = detect_host_ip(self.s.interface)
        if not host_ip:
            raise StackError(
                f"Can't determine host IP (interface={self.s.interface or 'default route'})"
            )

        st = self.status()
        if st.legacy and not recreate:
            raise NeedsRecreate(
                "Containers were created by the old bash script; recreate them "
                "(keys and peer config are kept)"
            )
        if st.drift and not recreate:
            self.log(
                f"Host IP changed ({st.server_url} -> {host_ip}): the client endpoint is stale. "
                "Recreate the container to regenerate the peer config.",
                "warning",
            )

        self.ensure_network()
        if recreate:
            self._remove(self._get(self.s.legacy_mitmproxy_name))
        self._ensure_forwarder(recreate)

        wg = self.wireguard
        if recreate:
            self._remove(wg)
            wg = None
        wg = wg or self._create_wireguard(host_ip)
        wg.reload()

        wg0 = self.s.wg_config_path / "wg_confs" / "wg0.conf"
        changed = self._patch_confs()

        if wg.status == "running":
            if changed:
                self.log("Restarting WireGuard container to apply the redirect hook", "info")
                wg.restart()
        else:
            self.log("Starting WireGuard container", "success")
            wg.start()

        if not wg0.is_file() or not self._has_hook():
            # Fresh /config: the image generates wg0.conf on first boot, patch it afterwards
            self.log("Waiting for the server to generate its config...", "info")
            if not self._wait_for(wg0.is_file, 30):
                raise StackError(f"{wg0} not generated, check `docker logs {self.s.container_name}`")
            if self._patch_confs():
                self.log("Restarting WireGuard container to apply the redirect hook", "info")
                wg.restart()

        if self._wait_for(lambda: self.redirect_counters() is not None, 20):
            host, port = self.s.dnat_target
            self.log(f"Redirect active: tcp/{self.s.redirected_tcp_ports} -> {host}:{port}", "success")
            return True
        self.log("Redirect rule not found in the container after start", "error")
        return False

    def _has_hook(self) -> bool:
        wg0 = self.s.wg_config_path / "wg_confs" / "wg0.conf"
        return wgconf.BEGIN in wg0.read_text(encoding="utf-8")

    def stop(self) -> None:
        for c in (self.wireguard, self.forwarder, self._get(self.s.legacy_mitmproxy_name)):
            if c and c.status == "running":
                self.log(f"Stopping {c.name}", "info")
                c.stop()

    def uninstall(self) -> None:
        self._remove(self.wireguard)
        self._remove(self.forwarder)
        self._remove(self._get(self.s.legacy_mitmproxy_name))
        try:
            self.client.networks.get(self.s.network_name).remove()
            self.log(f"Removed network {self.s.network_name}", "info")
        except NotFound:
            pass
        if self.s.config_path.exists():
            try:
                shutil.rmtree(self.s.config_path)
            except PermissionError as e:
                hint = "re-run with sudo" if is_linux() else "check no other process holds it open"
                raise StackError(f"Can't remove {self.s.config_path} ({e}); {hint}") from e
            self.log(f"Removed {self.s.config_path}", "info")

    # --- runtime introspection -------------------------------------------------

    def _exec(self, *cmd: str) -> str | None:
        wg = self.wireguard
        if not wg or wg.status != "running":
            return None
        try:
            code, out = wg.exec_run(list(cmd))
        except DockerException:
            return None
        return out.decode(errors="replace") if code == 0 else None

    def peer_config(self) -> str | None:
        path = self.s.peer_config_path
        if not path.is_file():
            return None
        lines = path.read_text(encoding="utf-8").splitlines()
        return "\n".join(l for l in lines if not l.strip().startswith("ListenPort"))

    def wg_peers(self) -> list[PeerInfo] | None:
        out = self._exec("wg", "show", "wg0", "dump")
        if out is None:
            return None
        peers = []
        for line in out.splitlines()[1:]:  # first line describes the interface
            f = line.split("\t")
            if len(f) < 7:
                continue
            peers.append(
                PeerInfo(
                    public_key=f[0],
                    endpoint=None if f[2] == "(none)" else f[2],
                    allowed_ips=f[3],
                    latest_handshake=int(f[4]),
                    rx=int(f[5]),
                    tx=int(f[6]),
                )
            )
        return peers

    def redirect_counters(self) -> tuple[int, int] | None:
        """(packets, bytes) of the DNAT rule for the current target; None if absent."""
        out = self._exec("iptables", "-t", "nat", "-L", "PREROUTING", "-v", "-x", "-n")
        if out is None:
            return None
        host, port = self.s.dnat_target
        for line in out.splitlines():
            f = line.split()
            if len(f) > 2 and f[2] == "DNAT" and f"to:{host}:{port}" in line:
                return int(f[0]), int(f[1])
        return None

    def apply_rule_now(self) -> bool:
        """Fallback: inject the rule directly (lost on next stop, hooks are the real fix)."""
        host, port = self.s.dnat_target
        rule = wgconf.dnat_rule(self.s.redirected_tcp_ports, host, port).replace("%i", "wg0")
        return self._exec("iptables", "-t", "nat", "-A", *rule.split()) is not None

    def proxy_reachable(self, timeout: float = 1.0) -> bool:
        """Is the intercepting proxy listening, as seen from the host?"""
        try:
            with socket.create_connection(self.s.proxy_check_target, timeout=timeout):
                return True
        except OSError:
            return False

    def path_reachable(self) -> bool | None:
        """Can the WireGuard container open a TCP connection to the DNAT target?

        Exercises the whole path (forwarder included) up to the proxy. None = can't tell.
        """
        wg = self.wireguard
        if not wg or wg.status != "running":
            return None
        host, port = self.s.dnat_target
        try:
            code, _ = wg.exec_run(["nc", "-z", "-w", "1", host, str(port)])
        except DockerException:
            return None
        if code in (126, 127):  # nc not available in the image
            return None
        return code == 0

    def events(self) -> Iterator[dict]:
        """Blocking stream of container events for the managed containers."""
        return self.client.events(
            filters={"type": "container", "label": ROLE_LABEL}, decode=True
        )
