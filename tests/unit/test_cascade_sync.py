"""
Синхронизация параметров каскада с релеем.

Смысл фичи: SNI и camouflage dest заданы на релее, и держать их копию на
панели вручную — источник тихих поломок. Панель забирает их сама.

Главный тест здесь — круговой: ссылка, собранная из ответа релея, обязана
разбираться собственным парсером каскада без потерь. Если эти две стороны
разойдутся хоть в одном поле, каскад сломается молча.
"""
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

    def test_label_with_spaces_survives(self):
        url = cascade_sync.build_url(dict(RELAY_ANSWER, label="Париж, выход"))
        self.assertEqual(cascade.parse_vless_url(url)["label"], "Париж, выход")


class EndpointTests(unittest.TestCase):
    def test_appends_api_path(self):
        self.assertEqual(cascade_sync._endpoint("http://203.0.113.10:8001"),
                         "http://203.0.113.10:8001/api/sync")

    def test_tolerates_trailing_slash(self):
        self.assertEqual(cascade_sync._endpoint("http://203.0.113.10:8001/"),
                         "http://203.0.113.10:8001/api/sync")

    def test_assumes_http_when_scheme_omitted(self):
        # Частый случай: вписали "1.2.3.4:8001" без схемы.
        self.assertEqual(cascade_sync._endpoint("203.0.113.10:8001"),
                         "http://203.0.113.10:8001/api/sync")

    def test_rejects_foreign_schemes(self):
        for bad in ("file:///etc/passwd", "ftp://203.0.113.10"):
            with self.subTest(url=bad), self.assertRaises(cascade_sync.SyncError):
                cascade_sync._endpoint(bad)

    def test_rejects_empty(self):
        with self.assertRaises(cascade_sync.SyncError):
            cascade_sync._endpoint("")


class FetchTests(unittest.TestCase):
    def test_requires_token(self):
        with self.assertRaises(cascade_sync.SyncError) as ctx:
            cascade_sync.fetch_params("http://203.0.113.10:8001", "")
        self.assertIn("токен", str(ctx.exception).lower())

    def test_reports_incomplete_answer(self):
        broken = {k: v for k, v in RELAY_ANSWER.items() if k != "sni"}
        with mock.patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value.__enter__.return_value.read.return_value = \
                __import__("json").dumps(broken).encode()
            with self.assertRaises(cascade_sync.SyncError) as ctx:
                cascade_sync.fetch_params("http://203.0.113.10:8001", "token")
        self.assertIn("sni", str(ctx.exception))


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
