"""
Генерация awg0.conf: правила PostUp/PostDown и клиентские конфиги.

test_postup_and_postdown_are_symmetric закрывает класс дефектов, из-за
которого на ru2 накопилось по семь копий каждого правила: любое правило,
добавленное в PostUp, обязано иметь парное удаление в PostDown.
"""
import contextlib
import ipaddress
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from app import awg_config, cascade
from app.models import ServerConfig


class _Server:
    """Минимальный дубль ServerConfig — без БД и SQLAlchemy."""

    interface_name = "awg0"
    private_key = "SERVER_PRIVATE_KEY="
    public_key = "SERVER_PUBLIC_KEY="
    address = "10.13.13.1/24"
    listen_port = 443
    dns = "1.1.1.1"
    mtu = 1420
    endpoint_host = "vpn.example.com"
    endpoint_host_v6 = ""
    ip_family = "4"
    client_endpoint_host = ServerConfig.client_endpoint_host
    egress_interface = "eth0"
    cascade_enabled = False
    cascade_vless_url = ""
    jc, jmin, jmax = 8, 40, 70
    s1 = s2 = s3 = s4 = 12
    h1, h2, h3, h4 = "1111", "2222", "3333", "4444"
    i1 = i2 = i3 = i4 = i5 = ""


class _Peer:
    name = "Ноутбук"
    public_key = "PEER_PUBLIC_KEY="
    private_key = "PEER_PRIVATE_KEY="
    preshared_key = "PEER_PSK="
    address = "10.13.13.2/32"
    allowed_ips_client = "0.0.0.0/0, ::/0"
    dns_override = None
    persistent_keepalive = 25
    enabled = True


@contextlib.contextmanager
def _setting(name: str, value):
    """Настройки — обычный pydantic-объект: подменяем поле на время теста."""
    from app.config import settings
    original = getattr(settings, name, None)
    object.__setattr__(settings, name, value)
    try:
        yield
    finally:
        object.__setattr__(settings, name, original)


def _hook(name: str, block: str) -> str:
    for line in block.splitlines():
        if line.startswith(name):
            return line.split("=", 1)[1].strip()
    return ""


class PostUpDownTests(unittest.TestCase):
    """
    Правила больше не собираются строкой в конфиге: PostUp/PostDown зовут
    noisefloor-rules, который держит их в собственных цепочках и очищает
    перед заполнением. Раньше повторный запуск дублировал правила — на
    проде накопилось по семь копий каждого набора.
    """

    def test_hooks_call_the_rules_script(self):
        block = awg_config.server_interface_block(_Server())
        self.assertIn("/usr/local/bin/noisefloor-rules up", _hook("PostUp", block))
        self.assertIn("/usr/local/bin/noisefloor-rules down", _hook("PostDown", block))

    def test_no_raw_iptables_left_in_config(self):
        # Ровно то, от чего уходим: сырые -A в конфиге не идемпотентны.
        for cascade_on in (False, True):
            with self.subTest(cascade=cascade_on):
                server = _Server()
                server.cascade_enabled = cascade_on
                block = awg_config.server_interface_block(server)
                self.assertNotIn("iptables -A", block)
                self.assertNotIn("iptables -t nat -A", block)

    def test_down_undoes_the_same_interface(self):
        block = awg_config.server_interface_block(_Server())
        up, down = _hook("PostUp", block), _hook("PostDown", block)
        for flag in ("--iface awg0", "--egress eth0"):
            self.assertIn(flag, up)
            self.assertIn(flag, down)

    def test_cascade_mode_off_when_cascade_disabled(self):
        block = awg_config.server_interface_block(_Server())
        self.assertIn("--mode off", _hook("PostUp", block))
        self.assertNotIn("--cascade-port", _hook("PostUp", block))

    def test_client_isolation_enabled_by_default(self):
        """Подключение к одному серверу не повод открывать устройствам
        доступ друг к другу."""
        up = _hook("PostUp", awg_config.server_interface_block(_Server()))
        self.assertIn("--isolate-clients", up)

    def test_client_isolation_can_be_turned_off(self):
        from app.config import settings
        original = settings.isolate_clients
        try:
            object.__setattr__(settings, "isolate_clients", False)
            up = _hook("PostUp", awg_config.server_interface_block(_Server()))
            self.assertNotIn("--isolate-clients", up)
        finally:
            object.__setattr__(settings, "isolate_clients", original)

    def test_cascade_enabled_passes_mode_and_port(self):
        server = _Server()
        server.cascade_enabled = True
        # По умолчанию (auto) на ядре 6.x — tproxy: только он заворачивает ещё
        # и UDP/QUIC/DNS, то есть делает то, что каскад обещает пользователю.
        with mock.patch.object(cascade.platform, "release", return_value="6.8.0-138-generic"):
            up = _hook("PostUp", awg_config.server_interface_block(server))
        self.assertIn("--mode tproxy", up)
        self.assertIn(f"--cascade-port {cascade.REDIRECT_PORT}", up)

    def test_auto_mode_on_old_kernel_falls_back_to_redirect(self):
        """На 5.15 TPROXY для TCP не работает — auto обязан выбрать redirect
        (и закрыть QUIC), иначе клиенты останутся без TCP вовсе."""
        server = _Server()
        server.cascade_enabled = True
        with mock.patch.object(cascade.platform, "release", return_value="5.15.0-119-generic"):
            up = _hook("PostUp", awg_config.server_interface_block(server))
        self.assertIn("--mode redirect", up)
        self.assertIn("--block-quic", up)


class ServerConfigTests(unittest.TestCase):
    def test_quic_is_blocked_in_redirect_mode(self):
        """В redirect-режиме UDP в каскад не заворачивается, а браузер
        предпочитает QUIC: без этого флага основная часть трафика идёт
        мимо каскада и с настоящим адресом сервера."""
        server = _Server()
        server.cascade_enabled = True
        with _setting("cascade_intercept_mode", "redirect"), _setting("cascade_block_quic", True):
            self.assertIn("--block-quic", _hook("PostUp", awg_config.server_interface_block(server)))
        with _setting("cascade_intercept_mode", "redirect"), _setting("cascade_block_quic", False):
            self.assertNotIn("--block-quic", _hook("PostUp", awg_config.server_interface_block(server)))

    def test_quic_is_blocked_in_tproxy_mode_too(self):
        """В tproxy QUIC едет через каскад поверх TCP-туннеля до релея:
        страницы грузились в 3-4 раза медленнее, чем по TCP, а иногда
        вставали до таймаута. Отказ сразу переводит браузер на TCP."""
        server = _Server()
        server.cascade_enabled = True
        with _setting("cascade_intercept_mode", "tproxy"), _setting("cascade_block_quic", True):
            self.assertIn("--block-quic", _hook("PostUp", awg_config.server_interface_block(server)))
        with _setting("cascade_intercept_mode", "tproxy"), _setting("cascade_block_quic", False):
            self.assertNotIn("--block-quic", _hook("PostUp", awg_config.server_interface_block(server)))

    def test_quic_is_not_blocked_without_cascade(self):
        # Без каскада клиент и так выходит с адреса сервера — резать незачем.
        with _setting("cascade_block_quic", True):
            self.assertNotIn("--block-quic", _hook("PostUp", awg_config.server_interface_block(_Server())))

    def test_dns_port_passed_only_when_dns_goes_through_cascade(self):
        server = _Server()
        server.cascade_enabled = True
        with _setting("cascade_intercept_mode", "redirect"), _setting("cascade_dns_via_cascade", True):
            up = _hook("PostUp", awg_config.server_interface_block(server))
            self.assertIn(f"--cascade-dns-port {cascade.DNS_REDIRECT_PORT}", up)
        with _setting("cascade_intercept_mode", "redirect"), _setting("cascade_dns_via_cascade", False):
            self.assertNotIn("--cascade-dns-port", _hook("PostUp", awg_config.server_interface_block(server)))

    def test_disabled_peers_are_not_rendered(self):
        enabled, disabled = _Peer(), _Peer()
        disabled.enabled = False
        disabled.public_key = "DISABLED_KEY="
        text = awg_config.full_server_config(_Server(), [enabled, disabled])
        self.assertIn("PEER_PUBLIC_KEY=", text)
        self.assertNotIn("DISABLED_KEY=", text)

    def test_server_block_has_listen_port_and_keys(self):
        text = awg_config.full_server_config(_Server(), [])
        self.assertIn("ListenPort = 443", text)
        self.assertIn("PrivateKey = SERVER_PRIVATE_KEY=", text)


class MtuTests(unittest.TestCase):
    def test_profile_keeps_packet_inside_link_mtu(self):
        for s4, expected in ((None, 1424), (0, 1424), (12, 1412), (20, 1404), (32, 1392)):
            self.assertEqual(awg_config.profile_mtu(s4), expected)
            self.assertLessEqual(20 + 8 + (s4 or 0) + 32 + expected, 1500)

    def test_default_1420_fragments_with_big_s4(self):
        # Проблема из плана: при S4 > 20 пакет на 1420 выходит за 1500.
        self.assertGreater(20 + 8 + 21 + 32 + 1420, 1500)

    def server(self, **values):
        server = _Server()
        server.mtu = None
        server.s4 = 32
        for key, value in values.items():
            setattr(server, key, value)
        return server

    def test_written_to_server_and_client(self):
        server = self.server()
        self.assertIn("MTU = 1392", awg_config.server_interface_block(server))
        self.assertIn("MTU = 1392", awg_config.client_config(_Peer(), server))

    def test_explicit_value_wins(self):
        server = self.server(mtu=1280)
        self.assertIn("MTU = 1280", awg_config.server_interface_block(server))
        self.assertIn("MTU = 1280", awg_config.client_config(_Peer(), server))


class Ipv6Tests(unittest.TestCase):
    def ready(self):
        patcher = mock.patch.object(awg_config, "ipv6_ready", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_address_pairs_with_ipv4(self):
        self.ready()
        address = awg_config.with_ipv6("10.13.13.1/24", _Server())
        ipv4, ipv6 = address.split(", ")
        self.assertEqual(ipv4, "10.13.13.1/24")
        interface = ipaddress.IPv6Interface(ipv6)
        self.assertEqual(interface.network.prefixlen, 120)
        self.assertEqual(int(interface.ip) & 0xffffffff, int(ipaddress.IPv4Address("10.13.13.1")))
        self.assertTrue(str(interface.ip).startswith("fd"))
        self.assertTrue(awg_config.with_ipv6("10.13.13.2/32", _Server()).endswith("/128"))

    def test_client_and_server_share_prefix(self):
        self.ready()
        server = ipaddress.IPv6Interface(awg_config.with_ipv6("10.13.13.1/24", _Server()).split(", ")[1])
        client = ipaddress.IPv6Interface(awg_config.with_ipv6("10.13.13.2/32", _Server()).split(", ")[1])
        self.assertIn(client.ip, server.network)

    def test_prefix_depends_only_on_server_key(self):
        other = _Server()
        other.private_key = "OTHER_KEY="
        self.assertEqual(awg_config.ula_prefix(_Server()), awg_config.ula_prefix(_Server()))
        self.assertNotEqual(awg_config.ula_prefix(_Server()), awg_config.ula_prefix(other))

    def test_in_all_configs(self):
        self.ready()
        peer = _Peer()
        server = _Server()
        self.assertRegex(awg_config.server_interface_block(server), r"Address = 10\.13\.13\.1/24, fd.*/120")
        self.assertRegex(awg_config.server_peer_block(peer, server), r"AllowedIPs = \S+, fd.*/128")
        client = awg_config.client_config(peer, server)
        self.assertRegex(client, r"Address = \S+, fd.*/128")
        self.assertIn("::/0", client)
        self.assertIn("--ipv6-reject", awg_config.server_interface_block(server))

    def test_not_ready_keeps_config(self):
        with mock.patch.object(awg_config, "ipv6_ready", return_value=False):
            block = awg_config.server_interface_block(_Server())
            client = awg_config.client_config(_Peer(), _Server())
        self.assertNotIn("fd", block.split("Address = ")[1].split("\n")[0])
        self.assertNotIn("--ipv6-reject", block)
        self.assertNotIn(", fd", client)

    def test_bad_address_is_left_alone(self):
        self.ready()
        self.assertEqual(awg_config.with_ipv6("not-an-ip", _Server()), "not-an-ip")


class Ipv6ReadyTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.proc = Path(tmp.name)
        for scope in ("all", "default"):
            (self.proc / scope).mkdir()
            (self.proc / scope / "disable_ipv6").write_text("0\n")
        for target, name, value in (
            (awg_config, "_PROC_IPV6", self.proc),
            (awg_config.shutil, "which", lambda name: "/usr/sbin/ip6tables"),
            (awg_config.settings, "client_ipv6_reject", True),
        ):
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_ready(self):
        self.assertTrue(awg_config.ipv6_ready(_Server()))

    def test_setting_turns_it_off(self):
        with mock.patch.object(awg_config.settings, "client_ipv6_reject", False):
            self.assertFalse(awg_config.ipv6_ready(_Server()))

    def test_disabled_on_host(self):
        (self.proc / "default" / "disable_ipv6").write_text("1\n")
        self.assertFalse(awg_config.ipv6_ready(_Server()))

    def test_ipv6_module_absent(self):
        (self.proc / "all" / "disable_ipv6").unlink()
        self.assertFalse(awg_config.ipv6_ready(_Server()))

    def test_no_ip6tables(self):
        with mock.patch.object(awg_config.shutil, "which", lambda name: None):
            self.assertFalse(awg_config.ipv6_ready(_Server()))

    def test_mtu_below_ipv6_minimum(self):
        server = _Server()
        server.mtu = 1279
        self.assertFalse(awg_config.ipv6_ready(server))


class ClientConfigTests(unittest.TestCase):
    def test_obfuscation_comes_from_server_not_peer(self):
        # Профиль обфускации общий на туннель: разойдётся — хендшейк не пройдёт.
        text = awg_config.client_config(_Peer(), _Server())
        for expected in ("Jc = 8", "Jmin = 40", "H1 = 1111", "H4 = 4444"):
            self.assertIn(expected, text)

    def test_endpoint_and_psk_present(self):
        text = awg_config.client_config(_Peer(), _Server())
        self.assertIn("Endpoint = vpn.example.com:443", text)
        self.assertIn("PresharedKey = PEER_PSK=", text)

    def test_ipv6_family_puts_v6_address_in_brackets(self):
        server = _Server()
        server.endpoint_host_v6 = "2a03:6f00:a::432b"
        server.ip_family = "6"
        self.assertIn("Endpoint = [2a03:6f00:a::432b]:443",
                      awg_config.client_config(_Peer(), server))

    def test_ipv4_family_ignores_stored_v6_address(self):
        server = _Server()
        server.endpoint_host_v6 = "2a03:6f00:a::432b"
        self.assertIn("Endpoint = vpn.example.com:443",
                      awg_config.client_config(_Peer(), server))

    def test_ipv6_family_without_v6_address_keeps_v4(self):
        # Переключатель без адреса не должен оставлять клиента с пустым Endpoint.
        server = _Server()
        server.ip_family = "6"
        self.assertIn("Endpoint = vpn.example.com:443",
                      awg_config.client_config(_Peer(), server))

    def test_peer_dns_override_wins(self):
        peer = _Peer()
        peer.dns_override = "9.9.9.9"
        self.assertIn("DNS = 9.9.9.9", awg_config.client_config(peer, _Server()))

    def test_placeholder_when_endpoint_host_not_set(self):
        server = _Server()
        server.endpoint_host = ""
        # Лучше явная заглушка, чем конфиг с пустым Endpoint, который клиент
        # молча импортирует и не подключится.
        self.assertIn("YOUR_SERVER_HOST_OR_IP", awg_config.client_config(_Peer(), server))



class TunnelMtuTests(unittest.TestCase):
    def test_awg20_mtu_follows_its_own_s4(self):
        server = types.SimpleNamespace(mtu=None)
        self.assertEqual(awg_config.tunnel_mtu(server, types.SimpleNamespace(s4=32)), 1392)

    def test_explicit_mtu_wins(self):
        server = types.SimpleNamespace(mtu=1280)
        self.assertEqual(awg_config.tunnel_mtu(server, types.SimpleNamespace(s4=32)), 1280)

    def test_tunnels_without_s4_keep_default(self):
        server = types.SimpleNamespace(mtu=None)
        self.assertIsNone(awg_config.tunnel_mtu(server, types.SimpleNamespace(s4=None)))


if __name__ == "__main__":
    unittest.main()
