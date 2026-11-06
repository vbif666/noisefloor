"""
Запасной вход VLESS: конфиг xray, ссылка клиента, занятый порт.
"""
import base64
import socket
import unittest
from types import SimpleNamespace
from unittest import mock
from urllib.parse import parse_qs, urlparse

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import cascade, fallback
from app.database import Base
from app.models import FallbackClient, FallbackConfig, ServerConfig

RELAY = {"uuid": "u", "host": "r", "port": 443, "flow": "xtls-rprx-vision", "sni": "s", "pbk": "p", "sid": "", "fp": "chrome"}
BACKUP = {**RELAY, "host": "r2"}
FB = {"port": 8443, "sni": "dl.google.com", "dest": "dl.google.com:443", "private_key": "k",
      "short_id": "ab", "clients": ["id-1", "id-2"]}


def inbound(config):
    found = [i for i in config["inbounds"] if i["tag"] == cascade.FALLBACK_TAG]
    return found[0] if found else None


def rules_of(config):
    return [r for r in config["routing"]["rules"] if cascade.FALLBACK_TAG in r.get("inboundTag", [])]


class ConfigTests(unittest.TestCase):
    def test_off_by_default_changes_nothing(self):
        self.assertEqual(cascade.build_xray_config(RELAY), cascade.build_xray_config(RELAY, fallback=None))
        self.assertIsNone(inbound(cascade.build_xray_config(RELAY)))
        self.assertEqual(rules_of(cascade.build_xray_config(RELAY)), [])

    def test_inbound(self):
        item = inbound(cascade.build_xray_config(RELAY, fallback=FB))
        self.assertEqual((item["listen"], item["port"], item["protocol"]), ("0.0.0.0", 8443, "vless"))
        self.assertEqual([c["id"] for c in item["settings"]["clients"]], ["id-1", "id-2"])
        self.assertTrue(all(c["flow"] == fallback.FLOW for c in item["settings"]["clients"]))
        self.assertEqual(item["settings"]["decryption"], "none")
        reality = item["streamSettings"]["realitySettings"]
        self.assertEqual((reality["dest"], reality["serverNames"], reality["shortIds"]),
                         ("dl.google.com:443", ["dl.google.com"], ["ab"]))

    def test_private_addresses_are_blocked_first(self):
        # Иначе клиент снаружи дотянулся бы до локальных служб. Панель не проверяет
        # адрес за него, как awg-интерфейс: это вход из интернета.
        rules = rules_of(cascade.build_xray_config(RELAY, fallback=FB))
        self.assertEqual(rules[0]["outboundTag"], "block")
        self.assertIn("127.0.0.0/8", rules[0]["ip"])
        self.assertIn("100.64.0.0/10", rules[0]["ip"])
        self.assertEqual(rules[1]["outboundTag"], "block")
        self.assertIn("full:localhost", rules[1]["domain"])
        self.assertEqual(rules[2]["outboundTag"], cascade.RELAY_TAG)

    def test_rules_come_before_anything_else_for_clients(self):
        tags = [r.get("ruleTag") for r in cascade.build_xray_config(RELAY, fallback=FB)["routing"]["rules"]]
        self.assertEqual(tags[:4], ["nf-api", "nf-vless-private", "nf-vless-local", "nf-vless"])

    def test_never_leaves_directly_when_all_relays_are_dead(self):
        # Балансировщик клиентов при direct выпускает с адреса сервера, а там
        # защиты от локальных адресов нет: имя разрешится уже здесь.
        config = cascade.build_xray_config(RELAY, reserves=[BACKUP], all_down="direct", fallback=FB)
        self.assertEqual(rules_of(config)[2]["balancerTag"], cascade.PROBE_BALANCER_TAG)
        fallbacks = {b["tag"]: b["fallbackTag"] for b in config["routing"]["balancers"]}
        self.assertEqual(fallbacks[cascade.PROBE_BALANCER_TAG], cascade.RELAY_TAG)

    def test_split_does_not_apply(self):
        config = cascade.build_xray_config(RELAY, split_ru_direct=True, fallback=FB)
        self.assertFalse(any(r.get("outboundTag") == "direct" for r in rules_of(config)))

    def test_change_of_clients_is_not_swapped_as_outbound(self):
        old = cascade.build_xray_config(RELAY, fallback=FB)
        new = cascade.build_xray_config(RELAY, fallback={**FB, "clients": ["id-1"]})
        self.assertIsNone(cascade._changed_outbounds(old, new))


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.old = (cascade._proc, cascade._last_config, cascade._fallback_warning)
        self.addCleanup(self.restore)

    def restore(self):
        cascade._proc, cascade._last_config, cascade._fallback_warning = self.old

    def resolve(self, last=None, running=False, free=True):
        with mock.patch.object(cascade, "is_running", return_value=running), \
                mock.patch.object(fallback, "params", return_value=FB), \
                mock.patch.object(fallback, "port_free", return_value=free):
            cascade._last_config = last
            return cascade._resolve_fallback(SimpleNamespace())

    def test_busy_port_drops_the_inbound_not_the_cascade(self):
        self.assertIsNone(self.resolve(free=False))
        self.assertIn("8443", cascade.fallback_warning())

    def test_own_port_is_not_busy(self):
        running = cascade.build_xray_config(RELAY, fallback=FB)
        self.assertEqual(self.resolve(last=running, running=True, free=False), FB)
        self.assertIsNone(cascade.fallback_warning())

    def test_new_port_is_checked_while_running(self):
        running = cascade.build_xray_config(RELAY, fallback={**FB, "port": 9443})
        self.assertIsNone(self.resolve(last=running, running=True, free=False))

    def test_listening(self):
        with mock.patch.object(cascade, "is_running", return_value=True):
            cascade._last_config = cascade.build_xray_config(RELAY, fallback=FB)
            self.assertTrue(cascade.fallback_listening())
            cascade._last_config = cascade.build_xray_config(RELAY)
            self.assertFalse(cascade.fallback_listening())

    def test_real_port_check(self):
        with socket.socket() as sock:
            sock.bind(("0.0.0.0", 0))
            sock.listen()
            self.assertFalse(fallback.port_free(sock.getsockname()[1]))


class ModelTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.addCleanup(self.db.close)

    def server(self):
        server = ServerConfig(private_key="a", public_key="b")
        self.db.add(server)
        self.db.commit()
        return server

    def test_disabled_until_turned_on(self):
        server = self.server()
        self.assertIsNone(fallback.params(server))
        config = fallback.get_config(self.db)
        self.assertFalse(config.enabled)
        self.db.add(fallback.new_client("a"))
        self.db.commit()
        self.assertIsNone(fallback.params(server))

    def test_only_enabled_clients(self):
        server = self.server()
        fallback.get_config(self.db).enabled = True
        one, two = fallback.new_client("a"), fallback.new_client("b")
        two.enabled = False
        self.db.add_all([one, two])
        self.db.commit()
        self.assertEqual(fallback.params(server)["clients"], [one.uuid])

    def test_no_enabled_clients_means_no_port(self):
        server = self.server()
        fallback.get_config(self.db).enabled = True
        self.db.commit()
        self.assertIsNone(fallback.params(server))

    def test_fake_server_is_ignored(self):
        self.assertIsNone(fallback.params(SimpleNamespace()))

    def test_link_parses_back(self):
        config = fallback.get_config(self.db)
        client = fallback.new_client("Телефон & планшет")
        parsed = cascade.parse_vless_url(fallback.client_link(config, client, "1.2.3.4"))
        self.assertEqual((parsed["uuid"], parsed["host"], parsed["port"]), (client.uuid, "1.2.3.4", 443))
        self.assertEqual((parsed["pbk"], parsed["sni"], parsed["sid"], parsed["flow"], parsed["label"]),
                         (config.public_key, config.sni, config.short_id, fallback.FLOW, "Телефон & планшет"))

    def test_link_with_ipv6_host(self):
        link = fallback.client_link(fallback.get_config(self.db), fallback.new_client("a"), "2001:db8::1")
        self.assertEqual(urlparse(link).hostname, "2001:db8::1")
        self.assertEqual(parse_qs(urlparse(link).query)["security"], ["reality"])

    def test_reality_keys_are_base64url_32_bytes(self):
        private, public = fallback.generate_reality_keys()
        for key in (private, public):
            self.assertNotIn("=", key)
            self.assertEqual(len(base64.urlsafe_b64decode(key + "=")), 32)

    def test_validation(self):
        self.assertTrue(fallback.valid_dest("dl.google.com:443"))
        self.assertFalse(fallback.valid_dest("dl.google.com"))
        self.assertFalse(fallback.valid_dest("a b:443"))
        self.assertFalse(fallback.valid_dest("dl.google.com:99999"))
        self.assertEqual(self.db.query(FallbackConfig).count(), 0)
        self.assertEqual(self.db.query(FallbackClient).count(), 0)


if __name__ == "__main__":
    unittest.main()
