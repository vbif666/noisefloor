"""
Уведомления: дедупликация, ограничение частоты, очередь и отправка. Сеть подменена.
"""
import json
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from app import cascade_sync, notify
from app.notify import Limiter


class Clock:
    def __init__(self):
        self.now = 10_000.0

    def __call__(self):
        return self.now


class LimiterTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.lim = Limiter(min_interval=300, max_per_hour=20, clock=self.clock)

    def test_first_observation_is_silent(self):
        self.lim.observe("k", True, "t")
        self.assertEqual(self.lim.due(), [])

    def test_bad_first_observation_can_speak(self):
        self.lim.observe("k", False, "упало", quiet_first=False)
        self.assertEqual(self.lim.due(), ["упало"])

    def test_same_value_is_deduplicated(self):
        self.lim.observe("k", True, "t")
        self.lim.observe("k", False, "упало")
        self.assertEqual(self.lim.due(), ["упало"])
        self.clock.now += 1000
        for _ in range(5):
            self.lim.observe("k", False, "упало")
            self.assertEqual(self.lim.due(), [])

    def test_blip_shorter_than_hold_says_nothing(self):
        self.lim.observe("k", True, "t")
        self.lim.observe("k", False, "упало", hold=120)
        self.clock.now += 60
        self.lim.observe("k", False, "упало", hold=120)
        self.assertEqual(self.lim.due(), [])
        self.lim.observe("k", True, "вернулось", hold=120)
        self.clock.now += 300
        self.assertEqual(self.lim.due(), [])

    def test_hold_counts_from_first_seen(self):
        self.lim.observe("k", True, "t")
        self.lim.observe("k", False, "упало", hold=120)
        self.clock.now += 130
        self.lim.observe("k", False, "упало", hold=120)
        self.assertEqual(self.lim.due(), ["упало"])

    def test_flapping_is_throttled_and_final_state_arrives(self):
        self.lim.observe("k", True, "t")
        self.lim.observe("k", False, "упало")
        self.assertEqual(self.lim.due(), ["упало"])
        self.clock.now += 10
        self.lim.observe("k", True, "вернулось")
        self.assertEqual(self.lim.due(), [])
        self.clock.now += 300
        self.assertEqual(self.lim.due(), ["вернулось"])

    def test_flap_back_within_interval_cancels(self):
        self.lim.observe("k", True, "t")
        self.lim.observe("k", False, "упало")
        self.lim.due()
        self.clock.now += 10
        self.lim.observe("k", True, "вернулось")
        self.clock.now += 10
        self.lim.observe("k", False, "упало")
        self.clock.now += 300
        self.assertEqual(self.lim.due(), [])

    def test_event_repeat_is_dropped_and_counted(self):
        self.assertEqual(self.lim.event("e", "раз"), "раз")
        self.assertIsNone(self.lim.event("e", "два"))
        self.clock.now += 301
        self.assertIn("пропущено: 1", self.lim.event("e", "три"))

    def test_hourly_cap(self):
        lim = Limiter(min_interval=0, max_per_hour=3, clock=self.clock)
        sent = [lim.event(f"e{i}", "x") for i in range(5)]
        self.assertEqual(sum(1 for s in sent if s), 3)
        lim.observe("k", True, "t")
        lim.observe("k", False, "упало")
        self.assertEqual(lim.due(), [], "лимит держит и отложенное")
        self.clock.now += 3601
        self.assertEqual(len(lim.due()), 1, "отложенное не потеряно")

    def test_state_survives_restart(self):
        self.lim.observe("k", True, "t")
        restored = Limiter(300, 20, clock=self.clock, state=json.loads(json.dumps(self.lim.dump())))
        restored.observe("k", False, "упало во время перезапуска")
        self.assertEqual(restored.due(), ["упало во время перезапуска"])


class ModuleCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = pathlib.Path(self.tmp.name)
        for target, value in (("CONFIG_PATH", root / "notify.json"), ("STATE_PATH", root / "state.json"),
                              ("_limiter", None), ("_queue", []),
                              ("_delivery", {"last_sent_at": None, "last_error": None})):
            patcher = mock.patch.object(notify, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        notify.save_config({"webhook_url": "https://hook.example/x", "telegram_token": "123:secret",
                            "telegram_chat_id": "42"})


class EnvBotTests(ModuleCase):
    def env(self):
        patcher = mock.patch.object(notify, "settings", SimpleNamespace(
            notify_telegram_token="1:env", notify_telegram_chat_id="7"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_env_works_without_saved_settings(self):
        self.env()
        notify.CONFIG_PATH.unlink()
        config = notify.load_config()
        self.assertEqual((config["telegram_token"], config["telegram_chat_id"]), ("1:env", "7"))
        self.assertTrue(notify.configured(config))

    def test_token_from_env_is_not_shown(self):
        self.env()
        notify.CONFIG_PATH.unlink()
        self.assertNotIn("1:env", json.dumps(notify.public_settings()))
        self.assertTrue(notify.public_settings()["telegram_token_set"])

    def test_saved_wins(self):
        self.env()
        self.assertEqual(notify.load_config()["telegram_token"], "123:secret")

    def test_cleared_in_interface_stays_cleared(self):
        self.env()
        notify.save_config({"webhook_url": "", "telegram_token": "", "telegram_chat_id": ""})
        self.assertFalse(notify.configured(notify.load_config()))

    def test_no_env_no_file_means_not_configured(self):
        notify.CONFIG_PATH.unlink()
        self.assertFalse(notify.configured(notify.load_config()))


class DeliveryTests(ModuleCase):
    def calls(self, code="200", running=True):
        run = mock.Mock(return_value=SimpleNamespace(stdout=code, stderr="", returncode=0))
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(notify.subprocess, "run", run).start()
        mock.patch("app.cascade.is_running", return_value=running).start()
        return run

    def test_secret_is_not_in_process_arguments(self):
        run = self.calls()
        self.assertIsNone(notify.send(notify.load_config(), 'кавычка " и \\ слэш'))
        for call in run.call_args_list:
            self.assertNotIn("secret", " ".join(call.args[0]))
        config_text = run.call_args_list[1].kwargs["input"]
        self.assertIn("/bot123:secret/sendMessage", config_text)
        self.assertIn('proxy = "socks5h://127.0.0.1:', config_text)

    def test_goes_through_cascade_first_then_direct(self):
        run = self.calls()
        run.side_effect = [SimpleNamespace(stdout="000", stderr="", returncode=7),
                           SimpleNamespace(stdout="200", stderr="", returncode=0),
                           SimpleNamespace(stdout="200", stderr="", returncode=0)]
        self.assertIsNone(notify.send(notify.load_config(), "x"))
        self.assertIn("proxy", run.call_args_list[0].kwargs["input"])
        self.assertNotIn("proxy", run.call_args_list[1].kwargs["input"])

    def test_direct_when_cascade_is_off(self):
        run = self.calls(running=False)
        notify.send(notify.load_config(), "x")
        self.assertNotIn("proxy", run.call_args_list[0].kwargs["input"])

    def test_failed_message_stays_queued_in_order(self):
        run = self.calls(code="500")
        with notify._lock:
            notify._queue.extend(["первое", "второе"])
        notify.deliver()
        self.assertEqual(notify._queue, ["первое", "второе"])
        self.assertIn("500", notify.public_settings()["last_error"])
        run.return_value = SimpleNamespace(stdout="200", stderr="", returncode=0)
        notify.deliver()
        self.assertEqual(notify._queue, [])
        self.assertIsNone(notify.public_settings()["last_error"])

    def test_one_channel_is_enough(self):
        run = self.calls()
        run.side_effect = [SimpleNamespace(stdout="500", stderr="", returncode=0)] * 2 + \
            [SimpleNamespace(stdout="200", stderr="", returncode=0)]
        self.assertIsNone(notify.send(notify.load_config(), "x"))
        self.assertIn("webhook", notify.public_settings()["last_error"])


class ModuleTests(ModuleCase):
    def test_token_never_leaves_public_settings(self):
        public = notify.public_settings()
        self.assertNotIn("123:secret", json.dumps(public))
        self.assertIs(public["telegram_token_set"], True)

    def test_nothing_queues_without_channels(self):
        notify.save_config({"webhook_url": "", "telegram_token": "", "telegram_chat_id": ""})
        notify.event("e", "текст")
        self.assertEqual(notify._queue, [])

    def test_event_survives_broken_state_path(self):
        with mock.patch.object(notify, "STATE_PATH", pathlib.Path(self.tmp.name) / "нет" / "state.json"):
            notify.event("e", "текст")
        self.assertEqual(len(notify._queue), 1)

    def test_queue_survives_restart(self):
        notify.event("e", "текст")
        notify._queue[:] = ["в очереди"]
        notify._save()
        with mock.patch.object(notify, "_limiter", None), mock.patch.object(notify, "_queue", []):
            notify.limiter()
            self.assertEqual(notify._queue, ["в очереди"])

    def test_url_validation(self):
        self.assertTrue(notify.valid_url("https://hook.example/x"))
        self.assertFalse(notify.valid_url("file:///etc/passwd"))
        self.assertFalse(notify.valid_url("hook.example"))


class SourceTests(ModuleCase):
    def setUp(self):
        super().setUp()
        self.lim = Limiter(0, 100, clock=Clock())

    def relays(self, active, count=2):
        patchers = [mock.patch("app.cascade.running_relay_count", return_value=count),
                    mock.patch("app.cascade.is_running", return_value=True),
                    mock.patch("app.cascade.active_relay", return_value=active),
                    mock.patch.object(notify.settings, "notify_hold_seconds", 0)]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_failover_and_all_down(self):
        self.relays("a")
        notify._observe_relays(self.lim, [])
        self.assertEqual(self.lim.due(), [])
        mock.patch.stopall()
        self.relays("b")
        notify._observe_relays(self.lim, [])
        self.assertIn("на релей b", self.lim.due()[0])
        mock.patch.stopall()
        self.relays(None)
        notify._observe_relays(self.lim, [])
        self.assertIn("все релеи недоступны", self.lim.due()[0])

    def test_single_relay_is_silent(self):
        self.relays(None, count=1)
        notify._observe_relays(self.lim, [])
        self.assertEqual(self.lim.dump()["known"], {})

    def test_pin_mismatch(self):
        self.relays(None, count=1)
        relay = SimpleNamespace(id=1, sync_url="https://r", sync_error=None)
        notify._observe_relays(self.lim, [relay])
        relay.sync_error = f"Ключ сертификата релея {notify.PIN_MISMATCH_MARK}. возможна подмена"
        notify._observe_relays(self.lim, [relay])
        self.assertIn("отпечаток релея https://r не совпал", self.lim.due()[0])

    def test_pin_mark_matches_real_message(self):
        # Сверка живёт в cascade_sync и не вызывает уведомления: совпадает только текст.
        self.assertIn(notify.PIN_MISMATCH_MARK, pathlib.Path(cascade_sync.__file__).read_text(encoding="utf-8"))

    def test_update_result(self):
        path = pathlib.Path(self.tmp.name) / "update-result.json"
        with mock.patch("app.self_update.RESULT_FILE", path):
            write = lambda **kw: path.write_text(json.dumps(kw), encoding="utf-8")
            write(finished_at="1", ok=True, rolled_back=False, **{"from": "v1", "to": "v2"})
            notify._observe_update(self.lim)
            self.assertEqual(self.lim.due(), [])
            write(finished_at="2", ok=True, rolled_back=False, **{"from": "v2", "to": "v2"})
            notify._observe_update(self.lim)
            self.assertEqual(self.lim.due(), [], "«уже актуально» не новость")
            write(finished_at="3", ok=True, rolled_back=False, **{"from": "v2", "to": "v3"})
            notify._observe_update(self.lim)
            self.assertIn("v2 -> v3", self.lim.due()[0])
            write(finished_at="4", ok=False, rolled_back=True, message="не поднялась", **{"from": "v3", "to": "v3"})
            notify._observe_update(self.lim)
            self.assertIn("откатилось", self.lim.due()[0])

    def test_backup_failure_and_recovery(self):
        status = {"last_success_at": None, "last_error": None}
        with mock.patch("app.backup.status", side_effect=lambda: dict(status)):
            notify._observe_backup(self.lim)
            self.assertEqual(self.lim.due(), [], "после перезапуска панели состояние неизвестно")
            status["last_error"] = "диск"
            notify._observe_backup(self.lim)
            self.assertIn("бэкап не удался: диск", self.lim.due()[0])
            status.update(last_error=None, last_success_at="сейчас")
            notify._observe_backup(self.lim)
            self.assertIn("снова", self.lim.due()[0])

    def test_canary_transitions(self):
        state = {"ok": None, "stage": None, "error": None}
        with mock.patch("app.canary.status", side_effect=lambda: dict(state)), \
                mock.patch.object(notify.settings, "notify_hold_seconds", 0):
            notify._observe_canary(self.lim)
            self.assertEqual(self.lim.dump()["known"], {})
            state["ok"] = True
            notify._observe_canary(self.lim)
            state.update(ok=False, stage="download", error="таймаут")
            notify._observe_canary(self.lim)
            self.assertIn("download: таймаут", self.lim.due()[0])
            state["ok"] = True
            notify._observe_canary(self.lim)
            self.assertIn("восстановилась", self.lim.due()[0])


if __name__ == "__main__":
    unittest.main()
