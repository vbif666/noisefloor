"""
Генерация awg0.conf: правила PostUp/PostDown и клиентские конфиги.

test_postup_and_postdown_are_symmetric закрывает класс дефектов, из-за
которого на ru2 накопилось по семь копий каждого правила: любое правило,
добавленное в PostUp, обязано иметь парное удаление в PostDown.
"""
import unittest

from app import awg_config, cascade


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


def _rules(line_prefix: str, block: str) -> list[str]:
    for line in block.splitlines():
        if line.startswith(line_prefix):
            return [r.strip() for r in line.split("=", 1)[1].split(";")]
    return []


class PostUpDownTests(unittest.TestCase):
    def test_postup_and_postdown_are_symmetric(self):
        """Каждому -A/-I в PostUp обязано соответствовать -D в PostDown."""
        for cascade_on in (False, True):
            with self.subTest(cascade=cascade_on):
                server = _Server()
                server.cascade_enabled = cascade_on
                block = awg_config.server_interface_block(server)
                added = [r.replace(" -A ", " -D ").replace(" -I ", " -D ")
                         for r in _rules("PostUp", block)]
                removed = _rules("PostDown", block)
                self.assertEqual(sorted(added), sorted(removed))

    def test_cascade_redirect_present_only_when_enabled(self):
        server = _Server()
        off = awg_config.server_interface_block(server)
        self.assertNotIn("REDIRECT", off)

        server.cascade_enabled = True
        on = awg_config.server_interface_block(server)
        self.assertIn(f"--to-ports {cascade.REDIRECT_PORT}", on)

    def test_masquerade_uses_egress_interface(self):
        block = awg_config.server_interface_block(_Server())
        self.assertIn("-t nat -A POSTROUTING -o eth0 -j MASQUERADE", block)


class ServerConfigTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
