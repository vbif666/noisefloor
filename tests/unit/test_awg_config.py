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

    def test_cascade_enabled_passes_mode_and_port(self):
        server = _Server()
        server.cascade_enabled = True
        up = _hook("PostUp", awg_config.server_interface_block(server))
        # По умолчанию tproxy: только он заворачивает ещё и UDP/QUIC/DNS,
        # то есть делает то, что каскад обещает пользователю.
        self.assertIn("--mode tproxy", up)
        self.assertIn(f"--cascade-port {cascade.REDIRECT_PORT}", up)


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
