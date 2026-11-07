"""
Перезапуск xray только по делу и SNI-маршрутизатор.

Перезапуск рвёт все соединения клиентов разом. Поэтому: конфиг не изменился -
процесс не трогаем, конфиг негодный - тоже не трогаем.
"""
import json
import unittest
from datetime import datetime, timezone
from unittest import mock

import app

NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)


def make_creds(rotation=False):
    creds = {
        "uuid": "u", "short_id": "s", "private_key": "p", "public_key": "P",
        "dest": "dl.google.com:443", "sni": "dl.google.com", "vless_port": 8443,
        "sync_token": "t", "rotation": app.rotation_defaults(),
    }
    creds["rotation"]["enabled"] = rotation
    creds["rotation"]["pool"] = ["dl.google.com", "www.amd.com", "www.dell.com"]
    return creds


def live_process():
    proc = mock.Mock()
    proc.poll.return_value = None
    return proc


class Base(unittest.TestCase):
    def setUp(self):
        self.restart = mock.patch.object(app, "restart_xray").start()
        self.xray_test = mock.patch.object(app, "_xray_test", return_value=None).start()
        mock.patch.object(app, "sync_router", return_value=False).start()
        mock.patch.object(app, "router_up", False).start()
        mock.patch.object(app, "xray_proc", live_process()).start()
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(lambda: app.state.update(config_error=None))

    def run_with(self, creds):
        """Как будто xray работает с этими настройками."""
        app._running_config_hash = app._config_hash(json.dumps(app.build_config(creds, NOW), indent=2))


class RestartOnlyOnChangeTests(Base):
    def test_same_config_keeps_process(self):
        creds = make_creds()
        self.run_with(creds)
        self.assertFalse(app.apply_config(creds, NOW))
        self.restart.assert_not_called()
        self.xray_test.assert_not_called()

    def test_changed_config_restarts(self):
        creds = make_creds()
        self.run_with(creds)
        creds["vless_port"] = 9443
        self.assertTrue(app.apply_config(creds, NOW))
        self.restart.assert_called_once()
        self.assertEqual(json.loads(app.CONFIG_FILE.read_text())["inbounds"][0]["port"], 9443)

    def test_pending_restart_is_not_treated_as_unchanged(self):
        # Вернули настройки, пока отложенный перезапуск не сработал: иначе
        # xray поднялся бы на файле, который уже ничему не соответствует.
        creds = make_creds()
        self.run_with(creds)
        creds["vless_port"] = 9443
        app.apply_config(creds, NOW)
        creds["vless_port"] = 8443
        self.assertTrue(app.apply_config(creds, NOW))
        self.assertEqual(json.loads(app.CONFIG_FILE.read_text())["inbounds"][0]["port"], 8443)

    def test_dead_process_is_not_treated_as_unchanged(self):
        creds = make_creds()
        self.run_with(creds)
        app.xray_proc.poll.return_value = 1
        self.assertTrue(app.apply_config(creds, NOW))

    def test_invalid_config_keeps_process_and_file(self):
        creds = make_creds()
        self.run_with(creds)
        app.render_config(creds, NOW)
        before = app.CONFIG_FILE.read_text()
        creds["vless_port"] = 9443
        self.xray_test.return_value = "плохой конфиг"
        with self.assertRaises(app.ConfigError):
            app.apply_config(creds, NOW)
        self.restart.assert_not_called()
        self.assertEqual(app.CONFIG_FILE.read_text(), before)
        self.assertEqual(app.state["config_error"], "плохой конфиг")

    def test_error_clears_after_good_config(self):
        creds = make_creds()
        self.run_with(creds)
        app.state["config_error"] = "старая"
        app.apply_config(creds, NOW)
        self.assertIsNone(app.state["config_error"])

    def test_rejected_camouflage_is_not_announced(self):
        # Иначе /api/sync отдал бы панели SNI, которого xray не примет.
        creds = make_creds()
        app.save_creds(creds)
        self.xray_test.return_value = "плохой конфиг"
        app._running_config_hash = None
        with self.assertRaises(app.ConfigError):
            app.apply_camouflage(creds, "www.amd.com:443", "www.amd.com", now=NOW)
        self.assertEqual(creds["sni"], "dl.google.com")
        self.assertEqual(app.load_creds()["sni"], "dl.google.com")


class RouterConfigTests(Base):
    def reality(self, creds):
        return app.build_config(creds, NOW)["inbounds"][0]["streamSettings"]["realitySettings"]

    def test_without_rotation_config_is_as_before(self):
        with mock.patch.object(app, "router_up", True):
            settings = self.reality(make_creds())
        self.assertEqual(settings["dest"], "dl.google.com:443")
        self.assertEqual(settings["serverNames"], ["dl.google.com"])

    def test_router_down_falls_back_to_direct_dest(self):
        settings = self.reality(make_creds(rotation=True))
        self.assertEqual(settings["dest"], "dl.google.com:443")

    def test_router_takes_whole_pool(self):
        with mock.patch.object(app, "router_up", True):
            settings = self.reality(make_creds(rotation=True))
        self.assertEqual(settings["dest"], f"127.0.0.1:{app.SNI_ROUTER_PORT}")
        self.assertEqual(settings["serverNames"], ["dl.google.com", "www.amd.com", "www.dell.com"])

    def test_rotation_does_not_change_config(self):
        creds = make_creds(rotation=True)
        with mock.patch.object(app, "router_up", True):
            before = app.build_config(creds, NOW)
            app.save_creds(creds)
            self.run_with(creds)
            app.apply_camouflage(creds, "www.amd.com:443", "www.amd.com", now=NOW)
            self.assertEqual(app.build_config(creds, NOW), before)
        self.restart.assert_not_called()

    def test_sni_outside_pool_stays_routable(self):
        creds = make_creds(rotation=True)
        creds.update(sni="own.example", dest="10.1.1.1:8443")
        self.assertEqual(app.router_routes(creds, NOW)["own.example"], "10.1.1.1:8443")

    def test_router_only_reaches_pool_hosts(self):
        creds = make_creds(rotation=True)
        conf = app.router_conf(app.router_routes(creds, NOW), creds["dest"])
        self.assertIn("www.amd.com www.amd.com:443;", conf)
        self.assertIn("default dl.google.com:443;", conf)
        self.assertNotIn("$ssl_preread_server_name:", conf)


if __name__ == "__main__":
    unittest.main()
