"""
Каскад: разбор vless://-ссылки и генерация конфига xray.

Тест test_cascade_inbound_listens_on_all_interfaces закрывает аварию
2026-09-05: cascade-in слушал 127.0.0.1, а iptables REDIRECT для пакетов
с awg0 переписывает destination на адрес входящего интерфейса (10.13.13.1),
не на loopback. Клиентские соединения получали RST, не доходя до xray, —
панель при этом бодро показывала "running: true".

Тесты RedirectModeConfigTests и TproxySockoptCheckTests закрывают аварию
2026-09-05 на третьем сервере: конфиг движка получал sockopt.tproxy независимо
от режима перехвата, и после nat REDIRECT xray обрывал каждое соединение с
"loopback connection detected", — а на ядре 5.15 движок вообще не может
сделать TCP-слушателя прозрачным, и TPROXY молча дропает весь клиентский TCP.
"""
import pathlib
import tempfile
import unittest
from unittest import mock

from app import cascade

VALID_URL = (
    "vless://00000000-0000-4000-8000-0000000000ff@203.0.113.10:8443"
    "?type=tcp&security=reality&pbk=EXAMPLEpublickeyEXAMPLEpublickeyEXAMPLEpub"
    "&fp=chrome&sni=dl.google.com&sid=0123456789abcdef&flow=xtls-rprx-vision"
    "#vpn-nd-reality"
)


class ParseVlessUrlTests(unittest.TestCase):
    def test_parses_all_fields(self):
        p = cascade.parse_vless_url(VALID_URL)
        self.assertEqual(p["uuid"], "00000000-0000-4000-8000-0000000000ff")
        self.assertEqual(p["host"], "203.0.113.10")
        self.assertEqual(p["port"], 8443)
        self.assertEqual(p["sni"], "dl.google.com")
        self.assertEqual(p["sid"], "0123456789abcdef")
        self.assertEqual(p["flow"], "xtls-rprx-vision")
        self.assertEqual(p["fp"], "chrome")
        self.assertEqual(p["label"], "vpn-nd-reality")

    def test_tolerates_surrounding_whitespace(self):
        # Ссылку почти всегда вставляют копипастом, часто с переносом строки.
        p = cascade.parse_vless_url("  " + VALID_URL + "\n")
        self.assertEqual(p["host"], "203.0.113.10")

    def test_rejects_non_reality_security(self):
        with self.assertRaises(cascade.VlessParseError):
            cascade.parse_vless_url(VALID_URL.replace("security=reality", "security=tls"))

    def test_rejects_missing_pbk(self):
        broken = VALID_URL.replace("&pbk=EXAMPLEpublickeyEXAMPLEpublickeyEXAMPLEpub", "")
        with self.assertRaises(cascade.VlessParseError):
            cascade.parse_vless_url(broken)

    def test_rejects_foreign_scheme(self):
        with self.assertRaises(cascade.VlessParseError):
            cascade.parse_vless_url("https://example.com/")

    def test_rejects_empty(self):
        with self.assertRaises(cascade.VlessParseError):
            cascade.parse_vless_url("")


class BuildXrayConfigTests(unittest.TestCase):
    def setUp(self):
        self.params = cascade.parse_vless_url(VALID_URL)
        self.config = cascade.build_xray_config(self.params)
        self.inbounds = {i["tag"]: i for i in self.config["inbounds"]}
        self.outbounds = {o["tag"]: o for o in self.config["outbounds"]}

    def test_cascade_inbound_listens_on_all_interfaces(self):
        """Регрессия на аварию с REDIRECT: слушать loopback здесь нельзя."""
        self.assertEqual(self.inbounds["cascade-in"]["listen"], "0.0.0.0")

    def test_cascade_inbound_port_matches_redirect_rule(self):
        # Порт в конфиге xray и порт в правиле iptables (awg_config) — одна
        # константа; расхождение молча выключает каскад целиком.
        self.assertEqual(self.inbounds["cascade-in"]["port"], cascade.REDIRECT_PORT)

    def test_cascade_inbound_accepts_udp_for_tproxy(self):
        """Без udp в network каскад не заворачивает QUIC и DNS — а это
        основная часть трафика современного браузера, уходившая мимо."""
        self.assertIn("udp", self.inbounds["cascade-in"]["settings"]["network"])

    def test_cascade_inbound_has_tproxy_sockopt(self):
        sockopt = self.inbounds["cascade-in"]["streamSettings"]["sockopt"]
        self.assertEqual(sockopt["tproxy"], "tproxy")

    def test_stats_api_stays_on_loopback(self):
        # А вот этот, наоборот, наружу торчать не должен.
        self.assertEqual(self.inbounds["api-in"]["listen"], "127.0.0.1")

    def test_outbound_carries_reality_params_from_url(self):
        reality = self.outbounds["cascade-out"]["streamSettings"]["realitySettings"]
        self.assertEqual(reality["serverName"], "dl.google.com")
        self.assertEqual(reality["publicKey"], self.params["pbk"])
        self.assertEqual(reality["shortId"], "0123456789abcdef")
        self.assertEqual(self.outbounds["cascade-out"]["streamSettings"]["security"], "reality")

    def test_all_intercepted_traffic_routed_to_cascade(self):
        rules = self.config["routing"]["rules"]
        cascade_rule = [r for r in rules if "cascade-in" in r.get("inboundTag", [])]
        self.assertEqual(len(cascade_rule), 1)
        self.assertEqual(cascade_rule[0]["outboundTag"], "cascade-out")

    def test_traffic_stats_enabled(self):
        # Без счётчиков нечем отличить "процесс жив" от "трафик идёт".
        self.assertTrue(self.config["policy"]["system"]["statsOutboundUplink"])
        self.assertTrue(self.config["policy"]["system"]["statsOutboundDownlink"])


class RedirectModeConfigTests(unittest.TestCase):
    """Вход каскада должен зависеть от режима перехвата.

    В redirect-режиме sockopt.tproxy не просто лишний, а ломающий: с ним xray
    берёт адрес назначения с прозрачного сокета, а после nat REDIRECT это
    адрес самого xray — соединение обрывается как петля."""

    def setUp(self):
        self.params = cascade.parse_vless_url(VALID_URL)

    def _cascade_in(self, mode):
        with mock.patch.object(cascade.settings, "cascade_intercept_mode", mode):
            config = cascade.build_xray_config(self.params)
        return {i["tag"]: i for i in config["inbounds"]}["cascade-in"]

    def test_redirect_mode_has_no_tproxy_sockopt(self):
        self.assertNotIn("streamSettings", self._cascade_in("redirect"))

    def test_redirect_mode_is_tcp_only(self):
        # UDP при REDIRECT до xray не доходит: у REDIRECT нет аналога для UDP.
        self.assertEqual(self._cascade_in("redirect")["settings"]["network"], "tcp")

    def test_tproxy_mode_keeps_tproxy_sockopt(self):
        inbound = self._cascade_in("tproxy")
        self.assertEqual(inbound["streamSettings"]["sockopt"]["tproxy"], "tproxy")
        self.assertIn("udp", inbound["settings"]["network"])


class TproxySockoptCheckTests(unittest.TestCase):
    """Если движок не смог включить IP_TRANSPARENT, ядро дропает весь TCP
    клиентов — а снаружи каскад выглядит здоровым. Панель обязана это
    заметить и назвать причину."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = pathlib.Path(self.tmp.name) / "cascade-xray.log"

    def _check(self, log_text, mode="tproxy", offset=0):
        self.log.write_text(log_text, encoding="utf-8")
        with mock.patch.object(cascade, "LOG_PATH", self.log), \
                mock.patch.object(cascade.settings, "cascade_intercept_mode", mode):
            return cascade._tproxy_sockopt_error(offset)

    def test_reports_failure_from_fresh_log(self):
        error = self._check("[Info] transport/internet: failed to set IP_TRANSPARENT > operation not supported\n")
        self.assertIsNotNone(error)
        self.assertIn("IP_TRANSPARENT", error)

    def test_silent_when_listener_is_transparent(self):
        self.assertIsNone(self._check("[Info] transport/internet/tcp: listening TCP on 0.0.0.0:12345\n"))

    def test_ignores_complaints_of_previous_run(self):
        # Лог не обнуляется при каждом старте: жалоба до offset — чужая.
        old = "[Info] failed to set IP_TRANSPARENT > operation not supported\n"
        fresh = "[Warning] core: Xray started\n"
        self.log.write_text(old + fresh, encoding="utf-8")
        with mock.patch.object(cascade, "LOG_PATH", self.log), \
                mock.patch.object(cascade.settings, "cascade_intercept_mode", "tproxy"):
            self.assertIsNone(cascade._tproxy_sockopt_error(len(old.encode())))

    def test_not_applicable_in_redirect_mode(self):
        # В redirect-режиме прозрачный сокет и не нужен.
        self.assertIsNone(self._check("failed to set IP_TRANSPARENT\n", mode="redirect"))


if __name__ == "__main__":
    unittest.main()
