import pytest

from vpn_proxy import wgconf

TEMPLATE = """[Interface]
Address = ${INTERFACE}.1
ListenPort = 51820
PrivateKey = $(cat /config/server/privatekey-server)
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth+ -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth+ -j MASQUERADE
"""

WG0 = """[Interface]
Address = 10.80.80.1
ListenPort = 51820
PrivateKey = xxx
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -i %i -j ACCEPT

[Peer]
# peer1
PublicKey = yyy
AllowedIPs = 10.80.80.2/32
"""

BLOCK = wgconf.render_block("80,443", "172.31.80.1", 8080)


def test_block_contents():
    assert "PostUp = iptables -t nat -A PREROUTING -i %i -p tcp -m multiport --dports 80,443 " \
           "-j DNAT --to-destination 172.31.80.1:8080" in BLOCK
    assert "PostDown = iptables -t nat -D PREROUTING" in BLOCK


def test_template_appends_at_end():
    new, changed = wgconf.patch(TEMPLATE, BLOCK)
    assert changed
    assert new.endswith(wgconf.END + "\n")
    assert new.startswith(TEMPLATE.rstrip("\n"))


def test_inserted_inside_interface_before_peer():
    new, _ = wgconf.patch(WG0, BLOCK)
    lines = new.splitlines()
    assert lines.index(wgconf.END) < lines.index("[Peer]")
    assert lines[lines.index(wgconf.BEGIN) - 1].startswith("PostDown")
    # blank separator before [Peer] preserved
    assert lines[lines.index("[Peer]") - 1] == ""


@pytest.mark.parametrize("text", [TEMPLATE, WG0])
def test_idempotent(text):
    once, _ = wgconf.patch(text, BLOCK)
    twice, changed = wgconf.patch(once, BLOCK)
    thrice, _ = wgconf.patch(twice, BLOCK)
    assert not changed
    assert once == thrice
    assert thrice.count(wgconf.BEGIN) == 1


def test_replaces_on_target_change():
    once, _ = wgconf.patch(WG0, BLOCK)
    other = wgconf.render_block("80,443,8443", "172.31.80.3", 8080)
    new, changed = wgconf.patch(once, other)
    assert changed
    assert "172.31.80.1" not in new
    assert "8443" in new
    assert new.count(wgconf.BEGIN) == 1


def test_no_interface_raises():
    with pytest.raises(ValueError):
        wgconf.patch("[Peer]\nPublicKey = x\n", BLOCK)


def test_patch_file(tmp_path):
    missing = tmp_path / "nope.conf"
    assert wgconf.patch_file(missing, BLOCK) is False
    f = tmp_path / "wg0.conf"
    f.write_text(WG0)
    assert wgconf.patch_file(f, BLOCK) is True
    assert wgconf.patch_file(f, BLOCK) is False
