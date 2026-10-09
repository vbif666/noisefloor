"""
Синхронизация параметров каскада с релеем.

Смысл фичи: SNI и camouflage dest заданы на релее, и держать их копию на
панели вручную — источник тихих поломок. Панель забирает их сама.

Главный тест здесь — круговой: ссылка, собранная из ответа релея, обязана
разбираться собственным парсером каскада без потерь. Если эти две стороны
разойдутся хоть в одном поле, каскад сломается молча.
"""
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from app import cascade, cascade_sync

RELAY_ANSWER = {
    "label": "relay-01",
    "codename": "Relay-01",
    "host": "203.0.113.10",
    "port": 8443,
    "uuid": "00000000-0000-4000-8000-0000000000ff",
    "public_key": "EXAMPLEpublickeyEXAMPLEpublickeyEXAMPLEpub",
    "short_id": "0123456789abcdef",
    "sni": "dl.google.com",
    "dest": "dl.google.com:443",
    "flow": "xtls-rprx-vision",
    "fp": "chrome",
}


class BuildUrlTests(unittest.TestCase):
    def test_url_parses_back_without_losses(self):
        """Круговой прогон: что собрали — то и разобрали."""
        url = cascade_sync.build_url(RELAY_ANSWER)
        parsed = cascade.parse_vless_url(url)

        self.assertEqual(parsed["uuid"], RELAY_ANSWER["uuid"])
        self.assertEqual(parsed["host"], RELAY_ANSWER["host"])
        self.assertEqual(parsed["port"], RELAY_ANSWER["port"])
        self.assertEqual(parsed["pbk"], RELAY_ANSWER["public_key"])
        self.assertEqual(parsed["sni"], RELAY_ANSWER["sni"])
        self.assertEqual(parsed["sid"], RELAY_ANSWER["short_id"])
        self.assertEqual(parsed["flow"], RELAY_ANSWER["flow"])
        self.assertEqual(parsed["label"], RELAY_ANSWER["label"])

    def test_falls_back_to_address_we_reached_relay_at(self):
        # Релей может не знать своего публичного адреса. Тот, по которому мы
        # только что до него достучались, заведомо рабочий.
        answer = dict(RELAY_ANSWER, host="YOUR-SERVER-IP")
        url = cascade_sync.build_url(answer, fallback_host="198.51.100.7")
        self.assertEqual(cascade.parse_vless_url(url)["host"], "198.51.100.7")

    def test_refuses_when_no_host_anywhere(self):
        with self.assertRaises(cascade_sync.SyncError):
            cascade_sync.build_url(dict(RELAY_ANSWER, host=""), fallback_host="")

    def test_ipv6_host_goes_in_brackets(self):
        # Без скобок "2a01::1:443" не разбирается обратно, и страница
        # каскада на панели падала с ошибкой 500.
        url = cascade_sync.build_url(dict(RELAY_ANSWER, host="2a03:6f02::261e"))
        self.assertIn("@[2a03:6f02::261e]:", url)
        parsed = cascade.parse_vless_url(url)
        self.assertEqual(parsed["host"], "2a03:6f02::261e")
        self.assertEqual(parsed["port"], RELAY_ANSWER["port"])

    def test_bare_ipv6_link_is_a_parse_error_not_a_crash(self):
        with self.assertRaises(cascade.VlessParseError):
            cascade.parse_vless_url(
                "vless://u@2a03:6f02::261e:443?security=reality&pbk=k&sni=dl.google.com")

    def test_label_with_spaces_survives(self):
        url = cascade_sync.build_url(dict(RELAY_ANSWER, label="Париж, выход"))
        self.assertEqual(cascade.parse_vless_url(url)["label"], "Париж, выход")


class EndpointTests(unittest.TestCase):
    def test_appends_api_path(self):
        self.assertEqual(cascade_sync._endpoint("https://203.0.113.10:8001"),
                         "https://203.0.113.10:8001/api/sync")

    def test_tolerates_trailing_slash(self):
        self.assertEqual(cascade_sync._endpoint("https://203.0.113.10:8001/"),
                         "https://203.0.113.10:8001/api/sync")

    def test_assumes_https_when_scheme_omitted(self):
        # Частый случай: вписали "1.2.3.4:8001" без схемы.
        self.assertEqual(cascade_sync._endpoint("203.0.113.10:8001"),
                         "https://203.0.113.10:8001/api/sync")

    def test_upgrades_old_http_address(self):
        # Адрес из прежних настроек с http:// не ломает каскад.
        self.assertEqual(cascade_sync._endpoint("http://203.0.113.10:8001"),
                         "https://203.0.113.10:8001/api/sync")

    def test_rejects_foreign_schemes(self):
        for bad in ("file:///etc/passwd", "ftp://203.0.113.10"):
            with self.subTest(url=bad), self.assertRaises(cascade_sync.SyncError):
                cascade_sync._endpoint(bad)

    def test_rejects_empty(self):
        with self.assertRaises(cascade_sync.SyncError):
            cascade_sync._endpoint("")


class PinTests(unittest.TestCase):
    def test_pin_bound_to_address(self):
        record = cascade_sync.make_pin_record("ab" * 32, "203.0.113.10:8001")
        self.assertEqual(cascade_sync._pin_for(record, "https://203.0.113.10:8001/"), "ab" * 32)
        # Другой адрес - отпечаток не применяется, запомнится заново.
        self.assertEqual(cascade_sync._pin_for(record, "https://203.0.113.11:8001"), "")

    def test_empty_record(self):
        self.assertEqual(cascade_sync._pin_for("", "https://203.0.113.10:8001"), "")
        self.assertEqual(cascade_sync._pin_for(None, "https://203.0.113.10:8001"), "")


def _make_cert(key=None, days=365):
    """Настоящий самоподписанный сертификат (DER) - как выпускает tls-cert.sh."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = key or ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "noisefloor")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    return key, cert.public_bytes(serialization.Encoding.DER)


KEY_A, CERT_A = _make_cert()
_, CERT_A_RENEWED = _make_cert(KEY_A, days=400)   # перевыпуск с тем же ключом
_, CERT_B = _make_cert()                           # другой ключ


def _fake_connection(cert=CERT_A, status=200, body=b"{}"):
    conn = mock.MagicMock()
    conn.sock.getpeercert.return_value = cert
    conn.getresponse.return_value.status = status
    conn.getresponse.return_value.read.return_value = body
    return conn


class FetchTests(unittest.TestCase):
    URL = "https://203.0.113.10:8001"

    def _fetch(self, cert, pin=""):
        conn = _fake_connection(cert=cert, body=json.dumps(RELAY_ANSWER).encode())
        with mock.patch("http.client.HTTPSConnection", return_value=conn):
            return conn, cascade_sync.fetch_params(self.URL, "token", pin)

    def test_requires_token(self):
        with self.assertRaises(cascade_sync.SyncError) as ctx:
            cascade_sync.fetch_params(self.URL, "")
        self.assertIn("токен", str(ctx.exception).lower())

    def test_reports_incomplete_answer(self):
        broken = {k: v for k, v in RELAY_ANSWER.items() if k != "sni"}
        conn = _fake_connection(body=json.dumps(broken).encode())
        with mock.patch("http.client.HTTPSConnection", return_value=conn):
            with self.assertRaises(cascade_sync.SyncError) as ctx:
                cascade_sync.fetch_params(self.URL, "token")
        self.assertIn("sni", str(ctx.exception))

    def test_returns_key_fingerprint(self):
        _, (params, fp) = self._fetch(CERT_A)
        self.assertEqual(params["uuid"], RELAY_ANSWER["uuid"])
        self.assertTrue(fp.startswith(cascade_sync.KEY_PIN_PREFIX))
        self.assertEqual(fp, cascade_sync.key_fingerprint(CERT_A))

    def test_renewed_cert_with_same_key_passes(self):
        # Главное: плановый перевыпуск сертификата на релее не ломает каскад.
        pin = cascade_sync.make_pin_record(cascade_sync.key_fingerprint(CERT_A), self.URL)
        _, (params, fp) = self._fetch(CERT_A_RENEWED, pin)
        self.assertEqual(params["sni"], RELAY_ANSWER["sni"])
        self.assertEqual(fp, cascade_sync.key_fingerprint(CERT_A))

    def test_changed_key_blocks_before_token_sent(self):
        pin = cascade_sync.make_pin_record(cascade_sync.key_fingerprint(CERT_A), self.URL)
        conn = _fake_connection(cert=CERT_B, body=json.dumps(RELAY_ANSWER).encode())
        with mock.patch("http.client.HTTPSConnection", return_value=conn):
            with self.assertRaises(cascade_sync.SyncError) as ctx:
                cascade_sync.fetch_params(self.URL, "token", pin)
        self.assertIn("Ключ", str(ctx.exception))
        conn.request.assert_not_called()

    def test_old_cert_pin_is_accepted_and_upgraded(self):
        # Записи прошлой версии хранят отпечаток всего сертификата.
        pin = cascade_sync.make_pin_record(cascade_sync.cert_fingerprint(CERT_A), self.URL)
        _, (_, fp) = self._fetch(CERT_A, pin)
        self.assertEqual(fp, cascade_sync.key_fingerprint(CERT_A))

    def test_old_cert_pin_still_blocks_other_cert(self):
        pin = cascade_sync.make_pin_record(cascade_sync.cert_fingerprint(CERT_A), self.URL)
        conn = _fake_connection(cert=CERT_B, body=json.dumps(RELAY_ANSWER).encode())
        with mock.patch("http.client.HTTPSConnection", return_value=conn):
            with self.assertRaises(cascade_sync.SyncError):
                cascade_sync.fetch_params(self.URL, "token", pin)
        conn.request.assert_not_called()

    def test_bad_token(self):
        conn = _fake_connection(status=401)
        with mock.patch("http.client.HTTPSConnection", return_value=conn):
            with self.assertRaises(cascade_sync.SyncError) as ctx:
                cascade_sync.fetch_params(self.URL, "token")
        self.assertIn("токен", str(ctx.exception))


class HostOfTests(unittest.TestCase):
    def test_extracts_host(self):
        self.assertEqual(cascade_sync.host_of("http://203.0.113.10:8001"), "203.0.113.10")
        self.assertEqual(cascade_sync.host_of("203.0.113.10:8001"), "203.0.113.10")
        self.assertEqual(cascade_sync.host_of("https://relay.example.com/"), "relay.example.com")


if __name__ == "__main__":
    unittest.main()


class RotationTimingTests(unittest.TestCase):
    """Релей меняет SNI по расписанию и объявляет момент заранее. Панель
    обязана прийти за новыми параметрами сразу после него: иначе каскад
    лежит до очередного пятиминутного опроса — ровно та тихая поломка,
    ради которой синхронизация и появилась."""

    NOW = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)

    def test_no_rotation_means_regular_interval(self):
        self.assertIsNone(cascade_sync.parse_next_rotation(RELAY_ANSWER))
        self.assertEqual(cascade_sync.wait_seconds(None, self.NOW),
                         cascade_sync.SYNC_INTERVAL_SECONDS)

    def test_disabled_rotation_is_ignored_even_with_a_time(self):
        answer = dict(RELAY_ANSWER, rotation={"enabled": False, "next_at": "2026-09-11T16:00:00+00:00"})
        self.assertIsNone(cascade_sync.parse_next_rotation(answer))

    def test_parses_announced_time(self):
        answer = dict(RELAY_ANSWER, rotation={"enabled": True, "next_at": "2026-09-11T16:00:00+00:00"})
        self.assertEqual(cascade_sync.parse_next_rotation(answer),
                         datetime(2026, 9, 11, 16, 0, tzinfo=timezone.utc))

    def test_garbage_time_does_not_break_sync(self):
        answer = dict(RELAY_ANSWER, rotation={"enabled": True, "next_at": "скоро"})
        self.assertIsNone(cascade_sync.parse_next_rotation(answer))

    def test_far_rotation_keeps_regular_interval(self):
        at = self.NOW + timedelta(hours=3)
        self.assertEqual(cascade_sync.wait_seconds(at, self.NOW), cascade_sync.SYNC_INTERVAL_SECONDS)

    def test_near_rotation_wakes_just_after_it(self):
        at = self.NOW + timedelta(seconds=60)
        self.assertEqual(cascade_sync.wait_seconds(at, self.NOW),
                         60 + cascade_sync.ROTATION_GRACE_SECONDS)

    def test_overdue_rotation_polls_at_floor_not_busily(self):
        # Релей объявил, но ещё не переключился: ждём, а не долбим.
        at = self.NOW - timedelta(seconds=30)
        self.assertEqual(cascade_sync.wait_seconds(at, self.NOW), cascade_sync.MIN_WAIT_SECONDS)
