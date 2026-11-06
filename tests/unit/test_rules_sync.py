"""
Сверка правил фаервола с ядром.

Раньше панель помнила аргументы последнего запуска и считала правила
стоящими, пока аргументы те же. Снесённые снаружи правила (ufw reset) так
оставались снесёнными, а «Применить» ничего не делал.
"""
import unittest
from types import SimpleNamespace
from unittest import mock

from app import config_sync
from app.awg_manager import CommandResult


def fake_rules_commands(_server, _interfaces):
    return (["/rules", "up", "--iface", "awg0"], ["/rules", "down", "--iface", "awg0"])


class EnsureRulesTests(unittest.TestCase):
    def setUp(self):
        with config_sync._rules_lock:
            config_sync._rules_status.update(ok=None, error=None, restored=0, last_restored_at=None)
        self.server = SimpleNamespace(egress_interface="eth0")

    def _run(self, *results, tools=True):
        run = mock.Mock(side_effect=list(results))
        with mock.patch.object(config_sync.awg_manager, "tools_available", return_value=tools), \
             mock.patch.object(config_sync.awg_manager, "run_rules", run), \
             mock.patch.object(config_sync.awg_config, "rules_commands", fake_rules_commands):
            result = config_sync.ensure_rules(self.server, ["awg0"])
        return result, run

    def test_nothing_is_touched_when_rules_are_in_place(self):
        _, run = self._run(CommandResult(True, ""))
        run.assert_called_once_with(["/rules", "check", "--iface", "awg0"])
        self.assertTrue(config_sync.rules_status()["ok"])

    def test_wiped_rules_are_restored_and_counted(self):
        _, run = self._run(CommandResult(False, "снесли", 4), CommandResult(True, ""))
        self.assertEqual(run.call_args_list[1].args[0], ["/rules", "up", "--iface", "awg0"])
        status = config_sync.rules_status()
        self.assertTrue(status["ok"])
        self.assertEqual(status["restored"], 1)
        self.assertIsNotNone(status["last_restored_at"])

    def test_changed_settings_are_not_counted_as_restoration(self):
        self._run(CommandResult(False, "другие настройки", 3), CommandResult(True, ""))
        self.assertEqual(config_sync.rules_status()["restored"], 0)

    def test_failure_is_reported(self):
        result, _ = self._run(CommandResult(False, "снесли", 4), CommandResult(False, "нет TPROXY", 1))
        self.assertFalse(result.ok)
        status = config_sync.rules_status()
        self.assertFalse(status["ok"])
        self.assertIn("TPROXY", status["error"])
        self.assertEqual(status["restored"], 0)

    def test_error_clears_after_recovery(self):
        self._run(CommandResult(False, "снесли", 4), CommandResult(False, "нет TPROXY", 1))
        self._run(CommandResult(True, ""))
        self.assertIsNone(config_sync.rules_status()["error"])

    def test_skipped_without_egress(self):
        self.server.egress_interface = None
        result, run = self._run()
        self.assertIsNone(result)
        run.assert_not_called()

    def test_skipped_without_tools(self):
        result, run = self._run(tools=False)
        self.assertIsNone(result)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
