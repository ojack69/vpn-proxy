"""Persist the redirect rule as wg-quick PostUp/PostDown hooks.

Rules injected with `docker exec` live only in the container's network namespace and vanish
on every stop. Hooks in the WireGuard config are re-run by wg-quick whenever wg0 comes up,
regardless of who restarted the container. Both the linuxserver template (used when the
image regenerates wg0.conf) and the live wg0.conf are patched.
"""

from __future__ import annotations

from pathlib import Path

BEGIN = "# vpn-proxy:begin"
END = "# vpn-proxy:end"


def dnat_rule(ports: str, host: str, port: int) -> str:
    return (
        f"PREROUTING -i %i -p tcp -m multiport --dports {ports} "
        f"-j DNAT --to-destination {host}:{port}"
    )


def render_block(ports: str, host: str, port: int) -> str:
    rule = dnat_rule(ports, host, port)
    return "\n".join(
        [
            BEGIN,
            f"PostUp = iptables -t nat -A {rule}",
            f"PostDown = iptables -t nat -D {rule}",
            END,
        ]
    )


def strip_block(lines: list[str]) -> list[str]:
    out: list[str] = []
    inside = False
    for line in lines:
        stripped = line.strip()
        if stripped == BEGIN:
            inside = True
        elif stripped == END:
            inside = False
        elif not inside:
            out.append(line)
    return out


def patch(text: str, block: str) -> tuple[str, bool]:
    """Place `block` at the end of the [Interface] section, replacing any previous one."""
    lines = strip_block(text.splitlines())

    try:
        iface = next(i for i, l in enumerate(lines) if l.strip().lower() == "[interface]")
    except StopIteration:
        raise ValueError("no [Interface] section found") from None

    idx = next(
        (i for i in range(iface + 1, len(lines)) if lines[i].strip().startswith("[")),
        len(lines),
    )
    while idx > iface + 1 and not lines[idx - 1].strip():
        idx -= 1

    lines[idx:idx] = block.splitlines()
    new = "\n".join(lines) + ("\n" if text.endswith("\n") or not text else "")
    return new, new != text


def patch_file(path: Path, block: str) -> bool:
    """Patch `path` in place; returns True if it changed. Missing files are skipped."""
    if not path.is_file():
        return False
    new, changed = patch(path.read_text(encoding="utf-8"), block)
    if changed:
        # Read by wg-quick inside the Linux container: never let Windows write CRLF
        path.write_text(new, encoding="utf-8", newline="\n")
    return changed
