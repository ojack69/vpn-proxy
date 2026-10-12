import os
from pathlib import Path

import pytest

from vpn_proxy import settings


@pytest.fixture
def me():
    pwd = pytest.importorskip("pwd")
    return pwd.getpwuid(os.getuid())


def test_defaults_match_bash_script(me, monkeypatch):
    monkeypatch.delenv("SUDO_USER", raising=False)
    s = settings.load(Path("/nonexistent/settings.toml"))
    assert s.vpn_subnet == "10.80.80.0"
    assert s.vpn_udp_port == 51820
    assert s.redirected_tcp_ports == "80,443"
    assert s.local_port == 8080
    assert s.container_name == "wg-proxy-vpn-server"
    assert s.config_path == Path(me.pw_dir) / ".wg-proxy-vpn"
    assert s.user.uid == me.pw_uid


def test_windows_user(monkeypatch):
    monkeypatch.setattr(settings.sys, "platform", "win32")
    u = settings.current_user()
    assert u.home == Path.home()
    assert (u.uid, u.gid) == (settings.DEFAULT_ID, settings.DEFAULT_ID)


def test_toml_override(tmp_path):
    f = tmp_path / "settings.toml"
    f.write_text('local_port = 9090\nredirected_tcp_ports = [80, 443, 8443]\ndocker_subnet = "10.99.0.0/24"\n')
    s = settings.load(f)
    assert s.local_port == 9090
    assert s.redirected_tcp_ports == "80,443,8443"
    assert (s.gateway_ip, s.wireguard_ip, s.forwarder_ip) == ("10.99.0.1", "10.99.0.2", "10.99.0.3")


def test_ports_normalized_and_validated(tmp_path):
    assert load(tmp_path, redirected_tcp_ports=" 80 , 443 ").redirected_tcp_ports == "80,443"
    assert load(tmp_path, redirected_tcp_ports="80,8000:8100").redirected_tcp_ports == "80,8000:8100"
    with pytest.raises(ValueError, match="at least one port"):
        load(tmp_path, redirected_tcp_ports=" , ")
    with pytest.raises(ValueError, match="out of range"):
        load(tmp_path, redirected_tcp_ports="80,70000")
    with pytest.raises(ValueError, match="range"):
        load(tmp_path, redirected_tcp_ports="443:80")
    with pytest.raises(ValueError, match="at most 15"):
        load(tmp_path, redirected_tcp_ports=",".join(str(p) for p in range(1, 17)))


def test_unknown_key_rejected(tmp_path):
    f = tmp_path / "settings.toml"
    f.write_text("lcoal_port = 1\n")
    with pytest.raises(ValueError, match="lcoal_port"):
        settings.load(f)


def test_sudo_user_resolves_home(me, monkeypatch):
    monkeypatch.setenv("SUDO_USER", me.pw_name)
    assert settings.current_user().home == Path(me.pw_dir)


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(settings.platform, "system", lambda: "Linux")


@pytest.fixture
def darwin(monkeypatch):
    monkeypatch.setattr(settings.platform, "system", lambda: "Darwin")


def load(tmp_path, **kw):
    return settings.load(tmp_path / "none.toml", **kw)


def test_default_mode_is_loopback(tmp_path):
    assert load(tmp_path).redirect == "loopback"


def test_loopback_linux(tmp_path, linux):
    s = load(tmp_path)
    assert s.dnat_target == ("172.31.80.1", 8080)
    assert s.proxy_check_target == ("127.0.0.1", 8080)
    spec = s.forwarder_spec()
    assert spec.host_network
    assert spec.command == [
        "TCP-LISTEN:8080,bind=172.31.80.1,range=172.31.80.2/32,fork,reuseaddr",
        "TCP:127.0.0.1:8080",
    ]


def test_loopback_non_linux(tmp_path, darwin):
    s = load(tmp_path, relay_port=9000)
    assert s.dnat_target == ("172.31.80.3", 9000)
    spec = s.forwarder_spec()
    assert not spec.host_network
    assert spec.command == ["TCP-LISTEN:9000,fork,reuseaddr", "TCP:host.docker.internal:8080"]


def test_bridge(tmp_path, linux):
    s = load(tmp_path, redirect="bridge")
    assert s.dnat_target == s.proxy_check_target == ("172.31.80.1", 8080)
    assert s.forwarder_spec() is None


def test_bridge_rejected_off_linux(tmp_path, darwin):
    with pytest.raises(ValueError, match="Linux"):
        load(tmp_path, redirect="bridge")


@pytest.mark.parametrize("platform_fixture", ["linux", "darwin"])
def test_custom(tmp_path, request, platform_fixture):
    request.getfixturevalue(platform_fixture)
    s = load(tmp_path, redirect="custom", proxy_host="192.168.1.50", local_port=8081)
    assert s.dnat_target == s.proxy_check_target == ("192.168.1.50", 8081)
    assert s.forwarder_spec() is None


def test_custom_requires_host(tmp_path):
    with pytest.raises(ValueError, match="proxy_host"):
        load(tmp_path, redirect="custom")


def test_invalid_mode(tmp_path):
    with pytest.raises(ValueError, match="redirect"):
        load(tmp_path, redirect="nope")


def test_cli_overrides_beat_file_and_none_ignored(tmp_path):
    f = tmp_path / "settings.toml"
    f.write_text("local_port = 9090\n")
    assert settings.load(f, local_port=None).local_port == 9090
    assert settings.load(f, local_port=7070).local_port == 7070


def test_save_overrides_roundtrip(tmp_path):
    f = tmp_path / "sub" / "settings.toml"
    settings.save_overrides(f, redirect="custom", proxy_host='10.0.0.5', local_port=8081)
    settings.save_overrides(f, redirected_tcp_ports=[80, 443, 8443])
    s = settings.load(f)
    assert (s.redirect, s.proxy_host, s.local_port) == ("custom", "10.0.0.5", 8081)
    assert s.redirected_tcp_ports == "80,443,8443"
    settings.save_overrides(f, redirect=None, proxy_host=None)
    assert settings.load(f).redirect == "loopback"
