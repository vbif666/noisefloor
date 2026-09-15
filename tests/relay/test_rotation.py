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
import threading
import time
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
        # Следующая попытка — скоро, а не через полный интервал: причина
        # отказа обычно минутная, а без этого ротация застряла бы на часы.
        self.assertEqual(datetime.fromisoformat(rot["next_at"]),
                         NOW + timedelta(seconds=app.ROTATION_RETRY_SECONDS))

    def test_slow_hosts_are_taken_when_nothing_is_within_budget(self):
        # Все хосты дальше бюджета (сеть моргнула) — берём самый быстрый из
        # годных по TLS, а не отказываемся от смены вовсе.
        def slow(dest, timeout=None):
            host = dest.split(":")[0]
            ms = {"www.samsung.com": 196, "www.amd.com": 59}.get(host, 80)
            return {"host": host, "ok": False, "slow": True, "ms": ms,
                    "error": f"рукопожатие {ms} мс — дальше бюджета 50 мс"}
        with mock.patch.object(app, "check_dest", side_effect=slow):
            rot = app.plan_next(self.creds, NOW)
        self.assertEqual(rot["next_sni"], "www.amd.com")
        self.assertIsNone(rot["last_error"])

    def test_within_budget_beats_faster_looking_but_slow_flags(self):
        def mixed(dest, timeout=None):
            host = dest.split(":")[0]
            if host == "www.amd.com":
                return good(dest)
            return {"host": host, "ok": False, "slow": True, "ms": 1,
                    "error": "рукопожатие 1 мс — дальше бюджета 0 мс"}
        with mock.patch.object(app, "check_dest", side_effect=mixed):
            rot = app.plan_next(self.creds, NOW)
        self.assertEqual(rot["next_sni"], "www.amd.com")

    def test_protocol_failures_are_never_taken(self):
        with mock.patch.object(app, "check_dest", side_effect=bad_for("www.samsung.com", "www.amd.com")):
            host, failures = app.pick_candidate(["www.samsung.com", "www.amd.com"], exclude="dl.google.com")
        self.assertIsNone(host)
        self.assertEqual(len(failures), 2)

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



class DestCriteriaTests(unittest.TestCase):
    """Критерии годности хоста — чистая функция, проверяется без сети."""

    def test_good_host_passes(self):
        self.assertEqual(app.dest_problems("TLSv1.3", "h2", 3000, 2, ms=12), [])

    def test_slow_host_is_rejected_even_if_otherwise_fine(self):
        problems = app.dest_problems("TLSv1.3", "h2", 3000, 2, ms=127, max_ms=50)
        self.assertEqual(len(problems), 1)
        self.assertIn("127 мс", problems[0])
        self.assertIn("50 мс", problems[0])

    def test_budget_is_inclusive(self):
        self.assertEqual(app.dest_problems("TLSv1.3", "h2", 3000, 2, ms=50, max_ms=50), [])

    def test_default_budget_comes_from_setting(self):
        with mock.patch.object(app, "DEST_MAX_HANDSHAKE_MS", 20):
            self.assertTrue(app.dest_problems("TLSv1.3", "h2", 3000, 2, ms=21))
            self.assertFalse(app.dest_problems("TLSv1.3", "h2", 3000, 2, ms=20))

    def test_protocol_problems_are_still_reported(self):
        problems = app.dest_problems("TLSv1.2", "http/1.1", 9000, 3, ms=5)
        self.assertEqual(len(problems), 3)

    def test_default_pool_is_fast_from_amsterdam_relay(self):
        # Пул по умолчанию проверен с релея в Амстердаме: все хосты ≤ 10 мс.
        # Тест защищает от возвращения «далёких» хостов при правке списка.
        for slow in ("www.samsung.com", "www.amd.com", "www.dell.com", "www.lenovo.com",
                     "www.cloudflare.com", "www.mozilla.org", "gateway.icloud.com"):
            self.assertNotIn(slow, app.ROTATION_DEFAULT_POOL)
        self.assertGreaterEqual(len(app.ROTATION_DEFAULT_POOL), 5)


class FakeProc:
    """Процесс, который завершается по terminate() — как настоящий xray."""
    started = []

    def __init__(self, *args, **kwargs):
        self.alive = True
        FakeProc.started.append(self)

    def poll(self):
        return None if self.alive else 0

    def terminate(self):
        self.alive = False

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.alive = False


class RestartRaceTests(unittest.TestCase):
    """restart_xray и watchdog не должны поднимать два процесса.

    Воспроизводит гонку с боевого сервера: в паузу между остановкой и
    запуском внутри restart_xray сторож видел завершённый процесс и
    запускал свой; итог — два xray на одном порту, один из них сирота."""

    def setUp(self):
        FakeProc.started = []
        mock.patch.object(app.subprocess, "Popen", FakeProc).start()
        self.addCleanup(mock.patch.stopall)
        app.xray_proc = None
        self.stop = app.threading.Event()

    def tearDown(self):
        app.xray_proc = None

    def test_watchdog_tick_during_restart_pause_does_not_spawn_second_process(self):
        app.start_xray()
        self.assertEqual(len(FakeProc.started), 1)
        pause_reached = app.threading.Event()
        ticks = []
        real_sleep = time.sleep

        def sleep_then_tick(seconds):
            # Пауза restart_xray: именно здесь раньше вклинивался сторож.
            # Даём ему реальный шанс вклиниться, прежде чем продолжить.
            pause_reached.set()
            real_sleep(0.2)

        def watchdog_side():
            pause_reached.wait(5)
            ticks.append(app.watchdog_tick(self.stop))

        t = threading.Thread(target=watchdog_side)
        t.start()
        with mock.patch.object(app.time, "sleep", side_effect=sleep_then_tick):
            app.restart_xray()
        t.join(5)
        # Сторож дождался конца перезапуска, увидел живой процесс и ничего
        # не поднял: ровно два Popen за всю историю — первый старт и перезапуск.
        self.assertEqual(ticks, [False])
        self.assertEqual(len(FakeProc.started), 2)
        self.assertIs(app.xray_proc, FakeProc.started[-1])
        self.assertTrue(app.xray_proc.alive)

    def test_watchdog_restarts_a_really_dead_process(self):
        app.start_xray()
        app.xray_proc.alive = False
        self.assertTrue(app.watchdog_tick(self.stop))
        self.assertEqual(len(FakeProc.started), 2)
        self.assertTrue(app.xray_proc.alive)

    def test_watchdog_does_nothing_when_stopping(self):
        app.start_xray()
        app.xray_proc.alive = False
        self.stop.set()
        self.assertFalse(app.watchdog_tick(self.stop))
        self.assertEqual(len(FakeProc.started), 1)


class RenderedPolicyTests(unittest.TestCase):
    """Таймауты в отрендеренном конфиге релея."""

    def test_half_close_timeouts_are_never_zero(self):
        # 0 для uplinkOnly/downlinkOnly в движке значит «закрыть немедленно»
        # (SetTimeout(0) -> finish()), а не «ждать»: каждый FIN от сайта
        # превращался в RST клиенту. Не меньше умолчаний движка (2/5).
        creds = {"uuid": "u", "short_id": "s", "private_key": "p", "public_key": "P",
                 "dest": "dl.google.com:443", "sni": "dl.google.com", "vless_port": 8443}
        app.render_config(creds, now=NOW)
        level = json.loads(app.CONFIG_FILE.read_text())["policy"]["levels"]["0"]
        self.assertGreaterEqual(level["uplinkOnly"], 2)
        self.assertGreaterEqual(level["downlinkOnly"], 5)
        self.assertGreater(level["connIdle"], 300)


class PortProvisioningTests(unittest.TestCase):
    """VLESS_PORT из окружения действует и на уже развёрнутом релее."""

    def _creds_file(self, port):
        creds = {"uuid": "u", "short_id": "s", "private_key": "p", "public_key": "P",
                 "dest": "dl.google.com:443", "sni": "dl.google.com", "vless_port": port,
                 "sync_token": "t", "rotation": app.rotation_defaults()}
        app.save_creds(creds)

    def test_explicit_env_port_overrides_stored_one(self):
        self._creds_file(8443)
        with mock.patch.object(app, "VLESS_PORT", 443), mock.patch.object(app, "VLESS_PORT_EXPLICIT", True):
            self.assertEqual(app.provision()["vless_port"], 443)
        self.assertEqual(json.loads(app.CREDS_FILE.read_text())["vless_port"], 443)

    def test_default_port_does_not_touch_existing_install(self):
        self._creds_file(8443)
        with mock.patch.object(app, "VLESS_PORT", 443), mock.patch.object(app, "VLESS_PORT_EXPLICIT", False):
            self.assertEqual(app.provision()["vless_port"], 8443)

    def test_fresh_install_gets_443(self):
        if app.CREDS_FILE.exists():
            app.CREDS_FILE.unlink()
        with mock.patch.object(app, "VLESS_PORT", 443), mock.patch.object(app, "run_x25519", return_value={"private_key": "p", "public_key": "P"}):
            self.assertEqual(app.provision()["vless_port"], 443)


if __name__ == "__main__":
    unittest.main()
