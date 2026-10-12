"""Command-line entry point: subcommands for scripting, TUI when run without arguments."""

from __future__ import annotations

import argparse
import io
import sys
import time
from pathlib import Path

import segno

from . import settings as settings_mod
from .stack import NeedsRecreate, Stack, StackError

COLORS = {"success": "\033[32m[>]\033[0m ", "error": "\033[31m[x]\033[0m ", "warning": "\033[36m[!]\033[0m "}


def log(message: str, level: str = "info") -> None:
    prefix = COLORS.get(level, "") if sys.stdout.isatty() else f"[{level}] " if level != "info" else ""
    print(f"{prefix}{message}")


def setup_console() -> None:
    """Windows: enable ANSI escapes on the legacy console, and keep the QR's block characters
    from crashing on a non-UTF-8 code page when stdout is redirected."""
    if sys.platform != "win32":
        return
    import ctypes

    kernel32 = ctypes.windll.kernel32
    handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
    mode = ctypes.c_uint32()
    if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    if not sys.stdout.isatty():
        sys.stdout.reconfigure(encoding="utf-8")


def qr_text(data: str) -> str:
    buf = io.StringIO()
    segno.make(data, error="l").terminal(out=buf, compact=True, border=2)
    return buf.getvalue()


PROXY_HINT = {
    "loopback": "start your proxy on 127.0.0.1 with invisible proxying enabled",
    "bridge": "bind your proxy to the docker bridge IP (or all interfaces) with invisible proxying",
    "custom": "start the proxy on that host with invisible proxying enabled",
}


def cmd_start(stack: Stack, args: argparse.Namespace) -> int:
    try:
        ok = stack.start(recreate=args.recreate)
    except NeedsRecreate as e:
        log(f"{e}. Run again with --recreate.", "error")
        return 1
    if ok and (conf := stack.peer_config()):
        print_config(conf)
    host, port = stack.s.proxy_check_target
    if not stack.proxy_reachable():
        log(f"Nothing is listening on {host}:{port}: {PROXY_HINT[stack.s.redirect]}", "warning")
    elif stack.path_reachable() is False:
        log(f"The VPN container can't reach {host}:{port}: check the host firewall", "warning")
    return 0 if ok else 1


def print_config(conf: str) -> None:
    print("\n" + "=" * 60)
    print(conf)
    print("=" * 60)
    print(qr_text(conf))


def cmd_stop(stack: Stack, args: argparse.Namespace) -> int:
    stack.stop()
    log("Done!", "success")
    return 0


def cmd_config(stack: Stack, args: argparse.Namespace) -> int:
    conf = stack.peer_config()
    if conf is None:
        log("VPN proxy not configured yet!", "error")
        return 1
    log(f"Client config file: {stack.s.peer_config_path}", "warning")
    print_config(conf)
    return 0


def cmd_uninstall(stack: Stack, args: argparse.Namespace) -> int:
    if not args.yes:
        answer = input("Remove containers, network, keys and config? y/N: ")
        if answer.strip().lower() not in ("y", "yes"):
            return 1
    stack.uninstall()
    log("Done!", "success")
    return 0


def cmd_status(stack: Stack, args: argparse.Namespace) -> int:
    st = stack.status()
    host, port = st.target
    print(f"wireguard      {st.wireguard}{'  (legacy, needs --recreate)' if st.legacy else ''}")
    if st.forwarder is not None:
        print(f"forwarder      {st.forwarder}")
    print(f"host ip        {st.host_ip}")
    print(f"endpoint       {st.server_url}{'  (STALE: host IP changed, use start --recreate)' if st.drift else ''}")
    print(f"redirect       {st.redirect}: tcp/{stack.s.redirected_tcp_ports} -> {host}:{port}")
    counters = stack.redirect_counters()
    print(f"dnat rule      {'missing' if counters is None else f'{counters[0]} pkts / {counters[1]} bytes'}")
    ph, pp = stack.s.proxy_check_target
    print(f"proxy          {ph}:{pp} {'listening' if stack.proxy_reachable() else 'NOT reachable'}")
    path = stack.path_reachable()
    print(f"path from vpn  {'-' if path is None else 'ok' if path else 'BLOCKED'}")
    now = int(time.time())
    for p in stack.wg_peers() or []:
        hs = f"{now - p.latest_handshake}s ago" if p.latest_handshake else "never"
        print(f"peer           {p.allowed_ips} endpoint={p.endpoint} handshake={hs} rx={p.rx} tx={p.tx}")
    return 0


COMMANDS = {
    "start": cmd_start,
    "stop": cmd_stop,
    "config": cmd_config,
    "uninstall": cmd_uninstall,
    "status": cmd_status,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vpn-proxy", description=__doc__)
    parser.add_argument("--settings", help="settings TOML (default ~/.wg-proxy-vpn/settings.toml)")
    sub = parser.add_subparsers(dest="command")
    p = sub.add_parser("start", help="create/start the VPN and apply the redirect")
    p.add_argument("--recreate", action="store_true", help="recreate containers (keys are kept)")
    p.add_argument(
        "--redirect",
        choices=settings_mod.REDIRECT_MODES,
        help="loopback: proxy on host 127.0.0.1 (default); bridge: proxy on the docker bridge IP; "
        "custom: proxy at --proxy-host. Saved to the settings file.",
    )
    p.add_argument("--proxy-host", help="proxy address for --redirect custom (saved)")
    p.add_argument("--local-port", type=int, help="proxy listening port (saved)")
    sub.add_parser("stop", help="stop the containers")
    sub.add_parser("config", help="print the client config and QR code")
    p = sub.add_parser("uninstall", help="remove containers, network and config")
    p.add_argument("-y", "--yes", action="store_true", help="don't ask for confirmation")
    sub.add_parser("status", help="print the current state")
    args = parser.parse_args(argv)
    setup_console()

    try:
        path = Path(args.settings) if args.settings else settings_mod.default_path()
        flags = {
            "redirect": getattr(args, "redirect", None),
            "proxy_host": getattr(args, "proxy_host", None),
            "local_port": getattr(args, "local_port", None),
        }
        s = settings_mod.load(path, **flags)  # validates before anything is persisted
        if any(v is not None for v in flags.values()):
            settings_mod.save_overrides(path, **{k: v for k, v in flags.items() if v is not None})
        if args.command is None:
            from .tui.app import VpnProxyApp

            VpnProxyApp(s, path).run()
            return 0
        stack = Stack(s, log)
        return COMMANDS[args.command](stack, args)
    except (StackError, ValueError) as e:
        log(str(e), "error")
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
