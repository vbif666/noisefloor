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


class LogAndTimeoutTests(unittest.TestCase):
    """Настройки движка, из-за которых каскад «иногда сбоит» и грызёт диск.

    Access-лог: движок пишет строку на каждое соединение клиента в тот же
    файл, куда идут ошибки, — на проде это 23 МБ за четыре дня и 138 тысяч
    строк, которые никто не читает.

    Таймауты: умолчания рассчитаны не на прокси. connIdle 300 закрывает
    молчащее пять минут соединение (ssh, imap, вебсокет мессенджера), а
    uplinkOnly/downlinkOnly добивают вторую половину соединения через
    считанные секунды после закрытия первой."""

    def setUp(self):
        self.config = cascade.build_xray_config(cascade.parse_vless_url(VALID_URL))

    def test_access_log_is_off(self):
        self.assertEqual(self.config["log"]["access"], "none")

    def test_errors_are_still_logged(self):
        # Без ошибок в логе не разобрать ни REALITY-хендшейк, ни IP_TRANSPARENT.
        self.assertEqual(self.config["log"]["loglevel"], "warning")

    def test_idle_connections_survive_longer_than_default(self):
        level = self.config["policy"]["levels"]["0"]
        self.assertGreater(level["connIdle"], 300)

    def test_half_closed_connections_are_not_cut_short(self):
        level = self.config["policy"]["levels"]["0"]
        self.assertEqual(level["uplinkOnly"], 0)
        self.assertEqual(level["downlinkOnly"], 0)


class SniffingByModeTests(unittest.TestCase):
    def _sniffing(self, mode):
        with mock.patch.object(cascade.settings, "cascade_intercept_mode", mode):
            config = cascade.build_xray_config(cascade.parse_vless_url(VALID_URL))
        return {i["tag"]: i for i in config["inbounds"]}["cascade-in"]["sniffing"]

    def test_redirect_mode_does_not_sniff_quic(self):
        # UDP до движка в этом режиме не доходит вовсе — разбирать нечего.
        self.assertNotIn("quic", self._sniffing("redirect")["destOverride"])

    def test_tproxy_mode_sniffs_quic(self):
        self.assertIn("quic", self._sniffing("tproxy")["destOverride"])


class DnsThroughCascadeTests(unittest.TestCase):
    """DNS клиентов в режиме redirect уходит напрямую с настоящим адресом
    сервера. По желанию его заворачивают в каскад отдельным слушателем:
    запрос идёт наружу по TCP через тот же VLESS-выход."""

    def _config(self, mode="redirect", enabled=True, dns="1.1.1.1"):
        with mock.patch.object(cascade.settings, "cascade_intercept_mode", mode), \
                mock.patch.object(cascade.settings, "cascade_dns_via_cascade", enabled, create=True):
            return cascade.build_xray_config(cascade.parse_vless_url(VALID_URL), dns)

    def test_off_by_default_leaves_config_untouched(self):
        tags = {i["tag"] for i in self._config(enabled=False)["inbounds"]}
        self.assertNotIn("dns-in", tags)

    def test_listener_matches_the_redirect_rule(self):
        inbound = {i["tag"]: i for i in self._config()["inbounds"]}["dns-in"]
        self.assertEqual(inbound["port"], cascade.DNS_REDIRECT_PORT)
        self.assertEqual(inbound["settings"]["network"], "udp")

    def test_query_leaves_through_the_cascade_over_tcp(self):
        config = self._config()
        out = {o["tag"]: o for o in config["outbounds"]}["dns-out"]
        self.assertEqual(out["settings"]["network"], "tcp")
        # Главное: наружу запрос идёт не сам по себе, а внутрь каскада.
        self.assertEqual(out["proxySettings"]["tag"], "cascade-out")
        rule = [r for r in config["routing"]["rules"] if "dns-in" in r.get("inboundTag", [])]
        self.assertEqual(rule[0]["outboundTag"], "dns-out")

    def test_uses_the_dns_server_from_settings(self):
        out = {o["tag"]: o for o in self._config(dns="9.9.9.9")["outbounds"]}["dns-out"]
        self.assertEqual(out["settings"]["address"], "9.9.9.9")

    def test_not_applicable_in_tproxy_mode(self):
        # Там DNS и так идёт через каскад вместе со всем UDP.
        tags = {i["tag"] for i in self._config(mode="tproxy")["inbounds"]}
        self.assertNotIn("dns-in", tags)


class TrafficStatsCacheTests(unittest.TestCase):
    """Счётчики спрашивают график (раз в 5 секунд) и каждый скрап /metrics,
    а каждый запрос — это запуск отдельного процесса `xray api`."""

    def setUp(self):
        cascade._stats_cache = (0.0, None)
        self.addCleanup(setattr, cascade, "_stats_cache", (0.0, None))

    def _run(self, *_a, **_kw):
        self.calls += 1
        return mock.Mock(returncode=0, stdout='{"stat":[{"name":"outbound>>>cascade-out>>>traffic>>>uplink","value":"10"}]}')

    def test_repeated_calls_hit_the_process_once(self):
        self.calls = 0
        with mock.patch.object(cascade, "is_running", return_value=True), \
                mock.patch.object(cascade.subprocess, "run", self._run):
            first = cascade.traffic_stats()
            second = cascade.traffic_stats()
        self.assertEqual(first, second)
        self.assertEqual(self.calls, 1)


if __name__ == "__main__":
    unittest.main()
