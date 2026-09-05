"""
Супервизия каскада: проба и её маршрутизация.

Каскад считается здоровым только если через него реально прошёл запрос.
Проверка «процесс жив» уже однажды месяц показывала running=true при
нулевых счётчиках — поэтому проба обязана идти тем же маршрутом, что и
клиентский трафик, и никуда больше.
"""
import unittest

from app import cascade

VALID_URL = (
    "vless://00000000-0000-4000-8000-0000000000ff@203.0.113.10:8443"
    "?type=tcp&security=reality&pbk=EXAMPLEpublickeyEXAMPLEpublickeyEXAMPLEpub"
    "&fp=chrome&sni=dl.google.com&sid=0123456789abcdef&flow=xtls-rprx-vision#relay"
)


class ProbeInboundTests(unittest.TestCase):
    def setUp(self):
        self.config = cascade.build_xray_config(cascade.parse_vless_url(VALID_URL))
        self.inbounds = {i["tag"]: i for i in self.config["inbounds"]}

    def test_probe_inbound_exists(self):
        self.assertIn("probe-in", self.inbounds)

    def test_probe_inbound_is_loopback_only(self):
        # Открытый наружу socks без авторизации — это публичный прокси.
        self.assertEqual(self.inbounds["probe-in"]["listen"], "127.0.0.1")

    def test_probe_goes_through_cascade_not_direct(self):
        rules = self.config["routing"]["rules"]
        probe = [r for r in rules if "probe-in" in r.get("inboundTag", [])]
        self.assertEqual(len(probe), 1, "у пробы должен быть ровно один маршрут")
        self.assertEqual(
            probe[0]["outboundTag"], "cascade-out",
            "проба обязана идти через каскад, иначе она проверяет не то",
        )

    def test_probe_port_differs_from_stats_and_redirect(self):
        ports = {i["port"] for i in self.config["inbounds"]}
        self.assertEqual(len(ports), len(self.config["inbounds"]), "порты входов не должны пересекаться")


class HealthTests(unittest.TestCase):
    def test_health_reports_unknown_before_first_check(self):
        health = cascade.health()
        for key in ("verified_ok", "verified_at", "verify_error", "restarts"):
            self.assertIn(key, health)

    def test_verify_fails_fast_when_process_is_down(self):
        # Без запущенного xray проба не должна висеть на таймауте curl.
        ok, error = cascade.verify()
        self.assertFalse(ok)
        self.assertIn("не запущен", error)


if __name__ == "__main__":
    unittest.main()
