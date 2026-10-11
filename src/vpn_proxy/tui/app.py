"""Textual TUI: live state of the VPN, the peer and the redirect, plus actions."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from rich.markup import escape
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    RadioButton,
    RadioSet,
    RichLog,
    Static,
)

from ..cli import qr_text
from .. import settings as settings_mod
from ..settings import REDIRECT_MODES, Settings, is_linux
from ..stack import NeedsRecreate, PeerInfo, Stack, StackError, Status

LEVEL_STYLE = {"success": "green", "error": "bold red", "warning": "yellow", "info": "default"}
WG_ROLE_EVENTS = {"start", "restart", "die", "stop", "create", "destroy"}


def human_bytes(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def state_markup(state: str | None) -> str:
    color = {"running": "green", "missing": "dim"}.get(state or "", "yellow")
    return f"[{color}]{state}[/]"


@dataclass
class Snapshot:
    status: Status
    peers: list[PeerInfo] | None
    counters: tuple[int, int] | None
    proxy_up: bool
    path_ok: bool | None


class ConfirmScreen(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "dismiss(False)", "Cancel")]

    def __init__(self, question: str) -> None:
        super().__init__()
        self.question = question

    def compose(self) -> ComposeResult:
        with Grid(id="confirm"):
            yield Label(self.question, id="question")
            with Horizontal(id="buttons"):
                yield Button("Yes", variant="error", id="yes")
                yield Button("No", variant="primary", id="no")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")


class ConfigScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape,c,q", "dismiss", "Close")]

    def __init__(self, conf: str, path: str) -> None:
        super().__init__()
        self.conf = conf
        self.path = path

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="config"):
            yield Static(f"[b]{escape(self.path)}[/]  [dim](esc to close)[/]")
            yield Static(qr_text(self.conf), id="qr")
            yield Static(escape(self.conf))


MODE_HELP = {
    "loopback": "Proxy on this host's 127.0.0.1 (a socat forwarder relays to it)",
    "bridge": "Proxy bound to the docker bridge IP or 0.0.0.0 (Linux only)",
    "custom": "Proxy at an arbitrary host, e.g. another machine on the LAN",
}


class TargetScreen(ModalScreen[Settings | None]):
    """Choose where redirected traffic goes; persisted to settings.toml."""

    BINDINGS = [Binding("escape", "dismiss(None)", "Cancel")]

    def __init__(self, current: Settings, path: Path) -> None:
        super().__init__()
        self.current = current
        self.path = path

    def compose(self) -> ComposeResult:
        with Grid(id="target"):
            yield Label("[b]Redirect target[/]")
            with RadioSet(id="mode"):
                for mode in REDIRECT_MODES:
                    yield RadioButton(
                        f"{mode}: {MODE_HELP[mode]}",
                        value=mode == self.current.redirect,
                        disabled=mode == "bridge" and not is_linux(),
                        name=mode,
                    )
            yield Input(self.current.proxy_host or "", placeholder="proxy host (custom only)", id="host")
            yield Input(str(self.current.local_port), placeholder="proxy port", id="port", type="integer")
            yield Label("", id="error")
            with Horizontal(id="buttons"):
                yield Button("Save", variant="primary", id="save")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self._sync_host()

    def _mode(self) -> str:
        pressed = self.query_one("#mode", RadioSet).pressed_button
        return pressed.name if pressed else self.current.redirect

    def _sync_host(self) -> None:
        self.query_one("#host", Input).disabled = self._mode() != "custom"

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        self._sync_host()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "save":
            self.dismiss(None)
            return
        mode = self._mode()
        host = self.query_one("#host", Input).value.strip() or None
        port = self.query_one("#port", Input).value.strip()
        values = {
            "redirect": mode,
            "local_port": int(port) if port else self.current.local_port,
            "proxy_host": host if mode == "custom" else self.current.proxy_host,
        }
        try:
            new = settings_mod.load(self.path, **values)
        except ValueError as e:
            self.query_one("#error", Label).update(f"[red]{escape(str(e))}[/]")
            return
        settings_mod.save_overrides(self.path, **values)
        self.dismiss(new)


class VpnProxyApp(App):
    TITLE = "VPN Proxy"
    CSS_PATH = "app.tcss"
    BINDINGS = [
        Binding("s", "start", "Start"),
        Binding("x", "stop", "Stop"),
        Binding("c", "config", "Client config"),
        Binding("t", "target", "Target"),
        Binding("r", "recreate", "Recreate"),
        Binding("u", "uninstall", "Uninstall"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, settings: Settings, settings_path: Path) -> None:
        super().__init__()
        self.settings = settings
        self.settings_path = settings_path
        self.stack: Stack | None = None
        self._events = None

    def compose(self) -> ComposeResult:
        yield Header()
        with Grid(id="panels"):
            yield Static(id="status", classes="panel")
            yield Static(id="peer", classes="panel")
            yield Static(id="redirect", classes="panel")
        yield RichLog(id="log", markup=True, wrap=True)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#status").border_title = "Server"
        self.query_one("#peer").border_title = "Peer"
        self.query_one("#redirect").border_title = "Redirect"
        self.query_one("#log").border_title = "Log"
        self.sub_title = f"redirect: {self.settings.redirect}"
        try:
            self.stack = Stack(self.settings, self.log_line)
        except StackError as e:
            self.write_log(str(e), "error")
            return
        self.poll()
        self.set_interval(2, self.poll)
        self.watch_events()

    def on_unmount(self) -> None:
        if self._events is not None:
            self._events.close()

    # --- logging ---------------------------------------------------------------

    def write_log(self, message: str, level: str = "info") -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        style = LEVEL_STYLE.get(level, "default")
        self.query_one("#log", RichLog).write(f"[dim]{ts}[/] [{style}]{escape(message)}[/]")

    def log_line(self, message: str, level: str = "info") -> None:
        """Thread-safe logger handed to Stack."""
        if threading.get_ident() == self._thread_id:
            self.write_log(message, level)
        else:
            try:
                self.call_from_thread(self.write_log, message, level)
            except RuntimeError:
                pass  # app shutting down

    # --- polling ---------------------------------------------------------------

    @work(thread=True, exclusive=True, group="poll")
    def poll(self) -> None:
        assert self.stack
        try:
            snap = Snapshot(
                status=self.stack.status(),
                peers=self.stack.wg_peers(),
                counters=self.stack.redirect_counters(),
                proxy_up=self.stack.proxy_reachable(),
                path_ok=self.stack.path_reachable(),
            )
        except Exception as e:  # docker hiccups shouldn't kill the UI
            self.log_line(f"Poll failed: {e}", "error")
            return
        self.call_from_thread(self.render_snapshot, snap)

    def render_snapshot(self, snap: Snapshot) -> None:
        st = snap.status
        s = self.settings
        host, port = st.target

        lines = [f"WireGuard   {state_markup(st.wireguard)}"]
        if st.forwarder is not None:
            lines.append(f"Forwarder   {state_markup(st.forwarder)}")
        lines.append(f"Host IP     {st.host_ip or '[red]unknown[/]'}")
        endpoint = f"{st.server_url}:{s.vpn_udp_port}" if st.server_url else "-"
        lines.append(f"Endpoint    {endpoint}")
        if st.legacy:
            lines.append("[bold red]Legacy container: press r to recreate[/]")
        if st.drift:
            lines.append("[bold red]Host IP changed: endpoint stale, press r[/]")
        self.query_one("#status", Static).update("\n".join(lines))

        if snap.peers is None:
            peer = "[dim]server not running[/]"
        elif not snap.peers:
            peer = "[dim]no peers[/]"
        else:
            now = int(time.time())
            out = []
            for p in snap.peers:
                if p.latest_handshake:
                    age = now - p.latest_handshake
                    color = "green" if age < 180 else "yellow"
                    hs = f"[{color}]{age}s ago[/]"
                else:
                    hs = "[dim]never[/]"
                out += [
                    f"Address     {p.allowed_ips}",
                    f"From        {p.endpoint or '-'}",
                    f"Handshake   {hs}",
                    f"Rx / Tx     {human_bytes(p.rx)} / {human_bytes(p.tx)}",
                ]
            peer = "\n".join(out)
        self.query_one("#peer", Static).update(peer)

        if snap.counters is None:
            rule = "[bold red]missing[/]" if st.wireguard == "running" else "[dim]-[/]"
        else:
            pkts, nbytes = snap.counters
            rule = f"[green]active[/]  {pkts} pkts / {human_bytes(nbytes)}"
        ph, pp = s.proxy_check_target
        proxy = f"{ph}:{pp} " + ("[green]listening[/]" if snap.proxy_up else "[bold red]down[/]")
        path = {None: "[dim]-[/]", True: "[green]ok[/]", False: "[bold red]blocked[/]"}[snap.path_ok]
        self.query_one("#redirect", Static).update(
            "\n".join(
                [
                    f"Mode        {st.redirect}",
                    f"Ports       tcp/{s.redirected_tcp_ports}",
                    f"DNAT to     {host}:{port}",
                    f"DNAT rule   {rule}",
                    f"Proxy       {proxy}",
                    f"VPN → proxy {path}",
                ]
            )
        )

    # --- docker events ---------------------------------------------------------

    @work(thread=True, group="events")
    def watch_events(self) -> None:
        assert self.stack
        self._events = self.stack.events()
        try:
            for ev in self._events:
                action = ev.get("Action") or ev.get("status") or ""
                attrs = ev.get("Actor", {}).get("Attributes", {})
                name, role = attrs.get("name", "?"), attrs.get("vpn-proxy.role")
                if action not in WG_ROLE_EVENTS:
                    continue
                self.log_line(f"docker: {name} {action}", "info")
                if role == "wireguard" and action == "start":
                    self.call_from_thread(self.verify_redirect)
        except Exception:
            pass  # stream closed on exit

    @work(thread=True, group="verify")
    def verify_redirect(self) -> None:
        """Check the hook re-created the rule after any (re)start, including external ones."""
        assert self.stack
        for _ in range(15):
            if self.stack.redirect_counters() is not None:
                self.log_line("Redirect rule present after container start", "success")
                return
            time.sleep(1)
        self.log_line("Redirect rule missing after container start, applying it directly", "error")
        if not self.stack.apply_rule_now():
            self.log_line("Failed to apply the redirect rule", "error")

    # --- actions ---------------------------------------------------------------

    def action_start(self) -> None:
        self.run_start(False)

    def action_recreate(self) -> None:
        def answer(yes: bool | None) -> None:
            if yes:
                self.run_start(True)

        self.push_screen(
            ConfirmScreen("Recreate the containers? Keys are kept, the peer config is re-rendered."),
            answer,
        )

    @work(thread=True, exclusive=True, group="action")
    def run_start(self, recreate: bool) -> None:
        if not self.stack:
            return
        try:
            self.stack.start(recreate=recreate)
        except NeedsRecreate as e:
            self.log_line(f"{e}. Press r to recreate.", "error")
        except Exception as e:
            self.log_line(f"Start failed: {e}", "error")
        self.call_from_thread(self.poll)

    @work(thread=True, exclusive=True, group="action")
    def action_stop(self) -> None:
        if not self.stack:
            return
        try:
            self.stack.stop()
            self.log_line("Stopped", "success")
        except Exception as e:
            self.log_line(f"Stop failed: {e}", "error")
        self.call_from_thread(self.poll)

    def action_target(self) -> None:
        def saved(new: Settings | None) -> None:
            if new is None:
                return
            self.settings = new
            if self.stack:
                self.stack.s = new
            self.sub_title = f"redirect: {new.redirect}"
            host, port = new.dnat_target
            self.write_log(f"Target saved: {new.redirect} -> {host}:{port}", "success")
            self.poll()

            def apply(yes: bool | None) -> None:
                if yes:
                    self.run_start(False)

            self.push_screen(ConfirmScreen("Apply now? The WireGuard container is restarted."), apply)

        self.push_screen(TargetScreen(self.settings, self.settings_path), saved)

    def action_config(self) -> None:
        if not self.stack:
            return
        conf = self.stack.peer_config()
        if conf is None:
            self.write_log("VPN proxy not configured yet, press s", "warning")
            return
        self.push_screen(ConfigScreen(conf, str(self.settings.peer_config_path)))

    def action_uninstall(self) -> None:
        def answer(yes: bool | None) -> None:
            if yes:
                self.run_uninstall()

        self.push_screen(
            ConfirmScreen("Uninstall? Containers, network, keys and config are deleted."), answer
        )

    @work(thread=True, exclusive=True, group="action")
    def run_uninstall(self) -> None:
        if not self.stack:
            return
        try:
            self.stack.uninstall()
            self.log_line("Uninstalled", "success")
        except Exception as e:
            self.log_line(f"Uninstall failed: {e}", "error")
        self.call_from_thread(self.poll)
