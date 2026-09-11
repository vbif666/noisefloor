"""
Ротация маскировки релея: выбор хоста, объявление заранее, такт планировщика.

Сетевая проверка хоста (check_dest) и перезапуск xray здесь подменены:
тесты про логику расписания, а не про то, отвечает ли dl.google.com.
Запускаются в образе релея с PYTHONPATH=/src и временным DATA_DIR — см.
CONTRIBUTING.
"""
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="relay-test-"))
os.environ.setdefault("ADMIN_PASSWORD", "test")

import app  # noqa: E402  (после DATA_DIR — модуль создаёт каталоги при импорте)

NOW = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)


def good(dest, timeout=None):
    return {"host": dest.split(":")[0], "ok": True, "tls": "TLSv1.3", "alpn": "h2", "cert_bytes": 3000, "ms": 10, "error": None}


def bad_for(*hosts):
    def check(dest, timeout=None):
        host = dest.split(":")[0]
        if host in hosts:
            return {"host": host, "ok": False, "error": "цепочка сертификатов 8300 байт — больше лимита REALITY"}
        return good(dest)
    return check


class PoolParsingTests(unittest.TestCase):
    def test_lines_commas_and_ports_are_tolerated(self):
        text = "dl.google.com:443\nwww.samsung.com, WWW.AMD.COM  www.dell.com/\n\n"
        self.assertEqual(app.parse_pool(text),
                         ["dl.google.com", "www.samsung.com", "www.amd.com", "www.dell.com"])

    def test_duplicates_and_garbage_are_dropped(self):
        self.assertEqual(app.parse_pool("a.com a.com <script> b.com"), ["a.com", "b.com"])


class RotationTests(unittest.TestCase):
    def setUp(self):
        self.creds = {
            "uuid": "u", "short_id": "s", "private_key": "p", "public_key": "P",
            "dest": "dl.google.com:443", "sni": "dl.google.com", "vless_port": 8443,
            "sync_token": "t", "rotation": app.rotation_defaults(),
        }
        self.creds["rotation"]["enabled"] = True
        self.creds["rotation"]["pool"] = ["dl.google.com", "www.samsung.com", "www.amd.com"]
        app.save_creds(self.creds)
        self.restart = mock.patch.object(app, "restart_xray").start()
        mock.patch.object(app, "render_config").start()
        self.addCleanup(mock.patch.stopall)

    def stored(self):
        return json.loads(app.CREDS_FILE.read_text())

    def test_plan_picks_another_host_and_announces_time(self):
        with mock.patch.object(app, "check_dest", side_effect=good):
            rot = app.plan_next(self.creds, NOW)
        self.assertIn(rot["next_sni"], ["www.samsung.com", "www.amd.com"])
        self.assertEqual(rot["next_dest"], rot["next_sni"] + ":443")
        self.assertEqual(datetime.fromisoformat(rot["next_at"]), NOW + timedelta(hours=4))
        self.assertIsNone(rot["last_error"])
        # Объявили, но не переключили: текущий SNI на месте, xray не трогали.
        self.assertEqual(self.stored()["sni"], "dl.google.com")
        self.restart.assert_not_called()

    def test_plan_skips_hosts_that_fail_the_check(self):
        with mock.patch.object(app, "check_dest", side_effect=bad_for("www.samsung.com")):
            rot = app.plan_next(self.creds, NOW)
        self.assertEqual(rot["next_sni"], "www.amd.com")

    def test_plan_reports_when_whole_pool_is_unusable(self):
        with mock.patch.object(app, "check_dest", side_effect=bad_for("www.samsung.com", "www.amd.com")):
            rot = app.plan_next(self.creds, NOW)
        self.assertIsNone(rot["next_sni"])
        self.assertIn("ни один хост", rot["last_error"])
        # Время следующей попытки всё равно назначено — иначе ротация
        # застряла бы навсегда после одного сбоя.
        self.assertIsNotNone(rot["next_at"])

    def test_rotate_applies_announced_host_and_plans_the_next(self):
        with mock.patch.object(app, "check_dest", side_effect=good):
            app.plan_next(self.creds, NOW)
            announced = self.stored()["rotation"]["next_sni"]
            rot = app.rotate_now(self.creds, now=NOW + timedelta(hours=4))
        stored = self.stored()
        self.assertEqual(stored["sni"], announced)
        self.assertEqual(stored["dest"], announced + ":443")
        self.restart.assert_called_once()
        self.assertNotEqual(rot["next_sni"], announced)
        self.assertEqual(datetime.fromisoformat(rot["next_at"]), NOW + timedelta(hours=8))
        self.assertEqual(rot["history"][0]["from"], "dl.google.com")
        self.assertEqual(rot["history"][0]["sni"], announced)

    def test_rotate_falls_back_when_announced_host_went_bad(self):
        with mock.patch.object(app, "check_dest", side_effect=good):
            app.plan_next(self.creds, NOW)
        announced = self.stored()["rotation"]["next_sni"]
        with mock.patch.object(app, "check_dest", side_effect=bad_for(announced)):
            rot = app.rotate_now(self.creds, now=NOW + timedelta(hours=4))
        self.assertNotEqual(self.stored()["sni"], announced)
        self.assertNotEqual(self.stored()["sni"], "dl.google.com")
        self.assertIn("не прошёл перепроверку", rot["history"][0]["note"])

    def test_tick_waits_until_announced_time(self):
        with mock.patch.object(app, "check_dest", side_effect=good):
            self.assertEqual(app.rotation_tick(NOW), "planned")
            self.assertEqual(app.rotation_tick(NOW + timedelta(hours=3)), "waiting")
            self.assertEqual(app.rotation_tick(NOW + timedelta(hours=4, seconds=20)), "rotated")
        self.restart.assert_called_once()

    def test_tick_does_not_switch_after_a_long_outage(self):
        # Контейнер лежал и проспал объявленный момент: панель первого
        # сервера ждала смену тогда, а не сейчас. Переобъявляем, не меняем.
        with mock.patch.object(app, "check_dest", side_effect=good):
            app.rotation_tick(NOW)
            self.assertEqual(app.rotation_tick(NOW + timedelta(hours=5)), "missed")
        self.restart.assert_not_called()
        self.assertEqual(datetime.fromisoformat(self.stored()["rotation"]["next_at"]),
                         NOW + timedelta(hours=9))

    def test_tick_is_idle_when_disabled(self):
        self.creds["rotation"]["enabled"] = False
        app.save_creds(self.creds)
        self.assertEqual(app.rotation_tick(NOW), "off")


class SniGraceTests(unittest.TestCase):
    """Прежний SNI живёт ещё окно после смены — иначе каскад на первом
    сервере лежит до его опроса. Проверено на живом xray: клиент со старым
    SNI из serverNames проходит при новом dest."""

    def setUp(self):
        self.creds = {
            "uuid": "u", "short_id": "s", "private_key": "p", "public_key": "P",
            "dest": "dl.google.com:443", "sni": "dl.google.com", "vless_port": 8443,
            "sync_token": "t", "rotation": app.rotation_defaults(),
        }
        app.save_creds(self.creds)
        mock.patch.object(app, "restart_xray").start()
        self.addCleanup(mock.patch.stopall)

    def rendered_names(self):
        cfg = json.loads(app.CONFIG_FILE.read_text())
        return cfg["inbounds"][0]["streamSettings"]["realitySettings"]["serverNames"]

    def test_previous_sni_stays_accepted_for_the_grace_window(self):
        app.apply_camouflage(self.creds, "www.amd.com:443", "www.amd.com", now=NOW)
        self.assertEqual(self.rendered_names(), ["www.amd.com", "dl.google.com"])
        self.assertEqual(app.active_server_names(self.creds, NOW + timedelta(minutes=14)),
                         ["www.amd.com", "dl.google.com"])
        self.assertEqual(app.active_server_names(self.creds, NOW + timedelta(minutes=16)),
                         ["www.amd.com"])

    def test_quick_double_switch_keeps_both_previous(self):
        # Два нажатия «Сменить сейчас» за минуту: панель может сидеть на
        # любом из трёх — все должны проходить.
        app.apply_camouflage(self.creds, "www.amd.com:443", "www.amd.com", now=NOW)
        app.apply_camouflage(self.creds, "www.dell.com:443", "www.dell.com", now=NOW + timedelta(minutes=1))
        self.assertEqual(self.rendered_names(), ["www.dell.com", "dl.google.com", "www.amd.com"])

    def test_switching_back_does_not_duplicate(self):
        app.apply_camouflage(self.creds, "www.amd.com:443", "www.amd.com", now=NOW)
        app.apply_camouflage(self.creds, "dl.google.com:443", "dl.google.com", now=NOW + timedelta(minutes=1))
        self.assertEqual(self.rendered_names(), ["dl.google.com", "www.amd.com"])

    def test_expired_entries_are_dropped_at_next_switch(self):
        app.apply_camouflage(self.creds, "www.amd.com:443", "www.amd.com", now=NOW)
        app.apply_camouflage(self.creds, "www.dell.com:443", "www.dell.com", now=NOW + timedelta(hours=4))
        self.assertEqual(self.rendered_names(), ["www.dell.com", "www.amd.com"])
        self.assertEqual([g["sni"] for g in self.creds["sni_grace"]], ["www.amd.com"])

    def test_sync_lists_accepted_snis(self):
        app.apply_camouflage(self.creds, "www.amd.com:443", "www.amd.com", now=datetime.now(timezone.utc))
        with mock.patch.object(app, "current_host", return_value="203.0.113.10"):
            payload = json.loads(app.api_sync().body)
        self.assertEqual(payload["sni"], "www.amd.com")
        self.assertEqual(payload["accepted_snis"], ["www.amd.com", "dl.google.com"])


class SyncPayloadTests(unittest.TestCase):
    def test_sync_announces_rotation_only_when_enabled(self):
        creds = {"uuid": "u", "short_id": "s", "private_key": "p", "public_key": "P",
                 "dest": "dl.google.com:443", "sni": "dl.google.com", "vless_port": 8443,
                 "sync_token": "t", "rotation": dict(app.rotation_defaults(), next_at="2026-09-11T16:00:00+00:00", next_sni="www.amd.com")}
        app.save_creds(creds)
        with mock.patch.object(app, "current_host", return_value="203.0.113.10"):
            off = json.loads(app.api_sync().body)
            creds["rotation"]["enabled"] = True
            app.save_creds(creds)
            on = json.loads(app.api_sync().body)
        self.assertIsNone(off["rotation"]["next_at"])
        self.assertEqual(on["rotation"]["next_at"], "2026-09-11T16:00:00+00:00")
        self.assertEqual(on["rotation"]["next_sni"], "www.amd.com")


if __name__ == "__main__":
    unittest.main()
