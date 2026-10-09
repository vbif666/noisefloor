"""
Четыре протокола клиентов: AmneziaWG 3.1 (основной интерфейс), AmneziaWG 2.0,
AmneziaWG 1.x и обычный WireGuard (дополнительные).

Маскировка задаётся на интерфейс, поэтому главное, что здесь закреплено:
клиент каждого протокола получает конфиг ровно своего интерфейса. Лишнее
поле в конфиге обычного WireGuard стандартное приложение не примет, а
поле 2.0 в конфиге 1.x не разберёт старый клиент. И наоборот, сервер не
должен описывать клиента не на том интерфейсе: там он не пройдёт
рукопожатие.
"""
import unittest
from unittest import mock

from fastapi import HTTPException

from app import awg_config, obfuscation
from app.routers import tunnels as tunnels_router


class _Server:
    interface_name = "awg0"
    private_key = "SERVER_PRIVATE_KEY="
    public_key = "SERVER_PUBLIC_KEY="
    address = "10.13.13.1/24"
    listen_port = 443
    dns = "1.1.1.1"
    mtu = 1420
    endpoint_host = "vpn.example.com"
    egress_interface = "eth0"
    cascade_enabled = False
    cascade_vless_url = ""
    jc, jmin, jmax = 8, 40, 70
    s1 = s2 = s3 = s4 = 12
    h1, h2, h3, h4 = "1111", "2222", "3333", "4444"
    i1, i2, i3, i4, i5 = "<b 0xf6ab>", "", "", "", ""


class _Tunnel:
    def __init__(self, protocol, iface, address, port):
        self.id = {"awg1": 1, "wg": 2, "awg20": 3}[protocol]
        self.protocol = protocol
        self.interface_name = iface
        self.enabled = True
        self.private_key = f"{iface}_PRIVATE="
        self.public_key = f"{iface}_PUBLIC="
        self.address = address
        self.listen_port = port
        self.s3 = self.s4 = 0
        if protocol == "awg1":
            self.jc, self.jmin, self.jmax, self.s1, self.s2 = 5, 50, 100, 10, 20
            self.h1, self.h2, self.h3, self.h4 = "5555", "6666", "7777", "8888"
        elif protocol == "awg20":
            self.jc, self.jmin, self.jmax, self.s1, self.s2 = 6, 60, 120, 3, 9
            self.s3, self.s4 = 7, 2
            self.h1, self.h2, self.h3, self.h4 = "9001", "9002", "9003", "9004"
        else:
            self.jc = self.jmin = self.jmax = self.s1 = self.s2 = 0
            self.h1 = self.h2 = self.h3 = self.h4 = ""


class _Peer:
    def __init__(self, name, protocol, address, enabled=True):
        self.name = name
        self.protocol = protocol
        self.public_key = f"{name}_PUB="
        self.private_key = f"{name}_PRIV="
        self.preshared_key = f"{name}_PSK="
        self.address = address
        self.allowed_ips_client = "0.0.0.0/0, ::/0"
        self.dns_override = None
        self.persistent_keepalive = 25
        self.enabled = enabled


AWG1 = _Tunnel("awg1", "awg-v1", "10.13.14.1/24", 51821)
WG = _Tunnel("wg", "wg-plain", "10.13.15.1/24", 51822)
AWG20 = _Tunnel("awg20", "awg-v2", "10.13.16.1/24", 51823)
PEERS = [
    _Peer("phone", "awg2", "10.13.13.2/32"),
    _Peer("router", "awg1", "10.13.14.2/32"),
    _Peer("laptop", "wg", "10.13.15.2/32"),
    _Peer("tablet", "awg20", "10.13.16.2/32"),
]


def _keys(conf: str) -> set[str]:
    return {line.split("=", 1)[0].strip() for line in conf.splitlines() if "=" in line}


class ServerSideTests(unittest.TestCase):
    def test_main_interface_serves_only_awg2_clients(self):
        conf = awg_config.full_server_config(_Server(), PEERS, ["awg-v1", "wg-plain"])
        self.assertIn("phone_PUB=", conf)
        self.assertNotIn("router_PUB=", conf)
        self.assertNotIn("laptop_PUB=", conf)

    def test_main_postup_covers_every_enabled_interface(self):
        # Правила общие: если PostUp основного интерфейса забудет про
        # дополнительные, их клиенты останутся без NAT и каскада.
        conf = awg_config.full_server_config(_Server(), PEERS, ["awg-v1", "wg-plain"])
        postup = next(line for line in conf.splitlines() if line.startswith("PostUp"))
        postdown = next(line for line in conf.splitlines() if line.startswith("PostDown"))
        for iface in ("awg0", "awg-v1", "wg-plain"):
            self.assertIn(f"--iface {iface}", postup)
            self.assertIn(f"--iface {iface}", postdown)

    def test_extra_interfaces_have_no_hooks(self):
        # Свой PostUp стёр бы правила соседей: цепочки общие.
        for tunnel in (AWG1, WG):
            conf = awg_config.tunnel_config(tunnel, _Server(), PEERS)
            self.assertNotIn("PostUp", conf)
            self.assertNotIn("PostDown", conf)

    def test_tunnel_serves_only_its_own_clients(self):
        awg1 = awg_config.tunnel_config(AWG1, _Server(), PEERS)
        wg = awg_config.tunnel_config(WG, _Server(), PEERS)
        self.assertIn("router_PUB=", awg1)
        self.assertNotIn("phone_PUB=", awg1)
        self.assertNotIn("laptop_PUB=", awg1)
        self.assertIn("laptop_PUB=", wg)
        self.assertNotIn("router_PUB=", wg)

    def test_disabled_client_not_rendered_on_tunnel(self):
        peers = [_Peer("old", "wg", "10.13.15.3/32", enabled=False)]
        self.assertNotIn("old_PUB=", awg_config.tunnel_config(WG, _Server(), peers))

    def test_awg1_interface_has_only_awg1_fields(self):
        keys = _keys(awg_config.tunnel_config(AWG1, _Server(), []))
        self.assertTrue({"Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"} <= keys)
        self.assertFalse({"S3", "S4", "I1"} & keys)
        self.assertIn("ListenPort", keys)

    def test_wg_interface_has_no_obfuscation(self):
        keys = _keys(awg_config.tunnel_config(WG, _Server(), []))
        self.assertFalse({"Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H4"} & keys)


class ClientSideTests(unittest.TestCase):
    def test_wg_client_is_plain_wireguard(self):
        conf = awg_config.client_config(PEERS[2], _Server(), WG)
        self.assertFalse({"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "I1"} & _keys(conf))
        self.assertIn("PublicKey = wg-plain_PUBLIC=", conf)
        self.assertIn("Endpoint = vpn.example.com:51822", conf)

    def test_awg1_client_gets_its_own_profile_without_2_0_fields(self):
        conf = awg_config.client_config(PEERS[1], _Server(), AWG1)
        keys = _keys(conf)
        self.assertFalse({"S3", "S4", "I1"} & keys)
        self.assertIn("H1 = 5555", conf)  # профиль туннеля, не основного интерфейса
        self.assertNotIn("H1 = 1111", conf)
        self.assertIn("PublicKey = awg-v1_PUBLIC=", conf)
        self.assertIn("Endpoint = vpn.example.com:51821", conf)

    def test_awg2_client_unchanged(self):
        conf = awg_config.client_config(PEERS[0], _Server())
        self.assertIn("S3 = 12", conf)
        self.assertIn("I1 = <b 0xf6ab>", conf)
        self.assertIn("Endpoint = vpn.example.com:443", conf)

    def test_ipv6_endpoint_in_brackets(self):
        server = _Server()
        server.endpoint_host = "2a03:6f02::261e"
        conf = awg_config.client_config(PEERS[2], server, WG)
        self.assertIn("Endpoint = [2a03:6f02::261e]:51822", conf)


class ObfuscationTests(unittest.TestCase):
    def test_init_and_response_never_same_size(self):
        for _ in range(500):
            s1, s2, _s3, _s4 = obfuscation.random_paddings()
            self.assertNotEqual(s1 + 56, s2)
            p = obfuscation.random_awg1_profile()
            self.assertNotEqual(p["s1"] + 56, p["s2"])

    def test_awg1_profile_has_no_2_0_fields(self):
        profile = obfuscation.random_awg1_profile()
        self.assertEqual(set(profile), {"jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"})
        self.assertEqual(len({profile[h] for h in ("h1", "h2", "h3", "h4")}), 4)


class ValidationTests(unittest.TestCase):
    def _obfs(self, **over):
        values = {"jc": 5, "jmin": 50, "jmax": 100, "s1": 10, "s2": 20,
                  "h1": "5555", "h2": "6666", "h3": "7777", "h4": "8888"}
        values.update(over)
        return values

    def test_valid_profile_passes(self):
        tunnels_router.validate_obfuscation(self._obfs())

    def test_bad_profiles_rejected(self):
        for bad in (
            {"jmin": 200, "jmax": 100},
            {"s1": 10, "s2": 66},
            {"h2": "5555"},
            {"h1": "abc"},
            {"h1": "3"},
        ):
            with self.subTest(bad=bad), self.assertRaises(HTTPException):
                tunnels_router.validate_obfuscation(self._obfs(**bad))

    def _patched(self):
        return (
            mock.patch.object(tunnels_router.config_sync, "get_server", return_value=_Server()),
            mock.patch.object(tunnels_router.config_sync, "get_tunnels", return_value=[AWG1, WG]),
        )

    def test_port_clash_with_main_or_other_tunnel(self):
        a, b = self._patched()
        with a, b:
            for port in (443, 51822):
                with self.subTest(port=port), self.assertRaises(HTTPException):
                    tunnels_router.validate_port(mock.MagicMock(), AWG1, port)
            tunnels_router.validate_port(mock.MagicMock(), AWG1, 51900)

    def test_subnet_overlap_rejected(self):
        a, b = self._patched()
        db = mock.MagicMock()
        db.query.return_value.filter.return_value.count.return_value = 0
        with a, b:
            for address in ("10.13.13.5/24", "10.13.15.1/24", "10.13.0.1/16"):
                with self.subTest(address=address), self.assertRaises(HTTPException):
                    tunnels_router.validate_address(db, AWG1, address)
            self.assertEqual(tunnels_router.validate_address(db, AWG1, "10.13.20.1/24"), "10.13.20.1/24")

    def test_subnet_change_refused_when_clients_exist(self):
        a, b = self._patched()
        db = mock.MagicMock()
        db.query.return_value.filter.return_value.count.return_value = 3
        with a, b, self.assertRaises(HTTPException):
            tunnels_router.validate_address(db, AWG1, "10.13.20.1/24")

    def test_ipv6_subnet_rejected(self):
        a, b = self._patched()
        with a, b, self.assertRaises(HTTPException):
            tunnels_router.validate_address(mock.MagicMock(), AWG1, "fd00::1/64")


class Awg20TunnelTests(unittest.TestCase):
    """Отдельный интерфейс AmneziaWG 2.0: после перевода основного на 3.1
    клиенты без поддержки 3.1 подключаются сюда."""

    def test_interface_has_2_0_fields_without_3_1(self):
        keys = _keys(awg_config.tunnel_config(AWG20, _Server(), PEERS))
        self.assertTrue({"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"} <= keys)
        self.assertFalse({"HeaderProtectionKey", "RekeyAfterTime", "I1"} & keys)

    def test_interface_serves_only_its_clients(self):
        conf = awg_config.tunnel_config(AWG20, _Server(), PEERS)
        self.assertIn("tablet_PUB=", conf)
        for other in ("phone_PUB=", "router_PUB=", "laptop_PUB="):
            self.assertNotIn(other, conf)

    def test_main_interface_does_not_serve_awg20_clients(self):
        conf = awg_config.full_server_config(_Server(), PEERS, ["awg-v2"])
        self.assertNotIn("tablet_PUB=", conf)

    def test_client_gets_tunnel_profile(self):
        server = _Server()
        server.header_protection_key = "HPK="
        conf = awg_config.client_config(PEERS[3], server, AWG20)
        self.assertIn("S3 = 7", conf)
        self.assertIn("H1 = 9001", conf)
        self.assertNotIn("H1 = 1111", conf)
        self.assertNotIn("HeaderProtectionKey", conf)
        self.assertIn("PublicKey = awg-v2_PUBLIC=", conf)
        self.assertIn("Endpoint = vpn.example.com:51823", conf)

    def test_profile_shape(self):
        for _ in range(200):
            p = obfuscation.random_awg20_profile()
            self.assertEqual(set(p), {"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4"})
            self.assertNotEqual(p["s1"] + 56, p["s2"])

    def test_s3_s4_editable_only_on_awg20(self):
        self.assertIn("s3", tunnels_router._PROTOCOL_FIELDS["awg20"])
        self.assertNotIn("s3", tunnels_router._PROTOCOL_FIELDS["awg1"])
        self.assertNotIn("wg", tunnels_router._PROTOCOL_FIELDS)


class HeaderProtectionPaddingTests(unittest.TestCase):
    """amneziawg-go с ключом защиты заголовков требует S1–S4 >= 12, иначе
    `awg setconf` отвечает "Invalid argument" и awg0 не поднимается
    (v1.0.12, сервер с S2=11, S4=5)."""

    LOW = obfuscation.HEADER_PROTECTION_MIN_PADDING

    def test_main_profile_respects_floor(self):
        for _ in range(500):
            p = obfuscation.random_obfuscation_profile()
            for f in ("s1", "s2", "s3", "s4"):
                self.assertGreaterEqual(p[f], self.LOW, f)
            self.assertNotEqual(p["s1"] + 56, p["s2"])
            self.assertTrue(p["header_protection_key"])

    def test_fix_replaces_only_small_values(self):
        for _ in range(200):
            obj = _Server()
            obj.s1, obj.s2, obj.s3, obj.s4 = 22, 11, 21, 5
            self.assertTrue(obfuscation.fix_header_protection_paddings(obj))
            self.assertEqual((obj.s1, obj.s3), (22, 21))  # подходящие не трогаем
            self.assertGreaterEqual(obj.s2, self.LOW)
            self.assertGreaterEqual(obj.s4, self.LOW)
            self.assertNotEqual(obj.s1 + 56, obj.s2)

    def test_fix_leaves_valid_profile(self):
        obj = _Server()
        obj.s1, obj.s2, obj.s3, obj.s4 = 32, 40, 61, 12
        self.assertFalse(obfuscation.fix_header_protection_paddings(obj))
        self.assertEqual((obj.s1, obj.s2, obj.s3, obj.s4), (32, 40, 61, 12))
