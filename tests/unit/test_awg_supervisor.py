"""
Надзор за интерфейсом туннеля.

Закрывает аварию 2026-09-20: OOM-killer убил amneziawg-go, awg0 исчез,
клиенты остались без VPN, а контейнер стоял «healthy» — проверялась только
веб-панель. Теперь здоровье контейнера = поднят ли туннель, которого ждут,
а фоновый надзор поднимает его сам.
"""
import threading
import unittest
from unittest import mock

from app import awg_supervisor


class FakeServer:
    interface_name = "awg0"
    last_apply_status = "ok"


class ExpectedUpTests(unittest.TestCase):
    def test_not_expected_without_tools(self):
        with mock.patch.object(awg_supervisor.awg_manager, "tools_available", return_value=False):
            self.assertFalse(awg_supervisor.expected_up(FakeServer()))

    def test_expected_when_auto_apply_on_start(self):
        with mock.patch.object(awg_supervisor.awg_manager, "tools_available", return_value=True), \
             mock.patch.object(awg_supervisor.settings, "auto_apply_on_start", True):
            server = FakeServer()
            server.last_apply_status = None
            self.assertTrue(awg_supervisor.expected_up(server))

    def test_expected_after_successful_apply_without_auto_apply(self):
        with mock.patch.object(awg_supervisor.awg_manager, "tools_available", return_value=True), \
             mock.patch.object(awg_supervisor.settings, "auto_apply_on_start", False):
            self.assertTrue(awg_supervisor.expected_up(FakeServer()))
            server = FakeServer()
            server.last_apply_status = "error"
            self.assertFalse(awg_supervisor.expected_up(server))


class HealthTests(unittest.TestCase):
    def setUp(self):
        with awg_supervisor._lock:
            awg_supervisor._health.update(
                expected_up=None, interface_up=None, checked_at=None, restarts=0, last_error=None
            )

    def test_healthy_before_first_check(self):
        # Иначе HEALTHCHECK ронял бы контейнер, пока панель только стартует.
        self.assertTrue(awg_supervisor.health()["ok"])

    def test_unhealthy_when_expected_interface_is_down(self):
        with mock.patch.object(awg_supervisor.awg_manager, "tools_available", return_value=True), \
             mock.patch.object(awg_supervisor.awg_manager, "interface_is_up", return_value=False), \
             mock.patch.object(awg_supervisor.settings, "auto_apply_on_start", True):
            self.assertFalse(awg_supervisor.check(FakeServer()))
        health = awg_supervisor.health()
        self.assertFalse(health["ok"])
        self.assertIn("awg0", health["last_error"])

    def test_healthy_when_interface_is_up(self):
        with mock.patch.object(awg_supervisor.awg_manager, "tools_available", return_value=True), \
             mock.patch.object(awg_supervisor.awg_manager, "interface_is_up", return_value=True):
            self.assertTrue(awg_supervisor.check(FakeServer()))
        self.assertTrue(awg_supervisor.health()["ok"])

    def test_healthy_when_tunnel_is_not_expected(self):
        # Генератор конфигов без живого управления — туннеля нет и не должно быть.
        with mock.patch.object(awg_supervisor.awg_manager, "tools_available", return_value=False):
            self.assertTrue(awg_supervisor.check(FakeServer()))
        self.assertTrue(awg_supervisor.health()["ok"])


class SuperviseTests(unittest.TestCase):
    """Один проход цикла: интерфейс пропал → apply_current_config → поднят."""

    def _run_one_pass(self, interface_states, apply_ok=True):
        stop = threading.Event()
        # wait() возвращает False на первом вызове (идём в цикл), True потом.
        waits = iter([False, True, True, True])
        stop.wait = lambda *_: next(waits)

        result = mock.Mock(ok=apply_ok, output="" if apply_ok else "awg-quick: ошибка")
        states = iter(interface_states)
        fake_db = mock.MagicMock()
        fake_db.query.return_value.first.return_value = FakeServer()

        with mock.patch.object(awg_supervisor.awg_manager, "tools_available", return_value=True), \
             mock.patch.object(awg_supervisor.awg_manager, "interface_is_up", side_effect=lambda *_: next(states)), \
             mock.patch.object(awg_supervisor.settings, "auto_apply_on_start", True), \
             mock.patch("app.config_sync.apply_current_config", return_value=result) as apply, \
             mock.patch("app.database.SessionLocal", return_value=fake_db):
            awg_supervisor.supervise(stop)
        return apply

    def setUp(self):
        with awg_supervisor._lock:
            awg_supervisor._health.update(expected_up=None, interface_up=None, restarts=0, last_error=None)

    def test_reapplies_when_interface_disappeared(self):
        apply = self._run_one_pass([False, True])
        apply.assert_called_once()
        health = awg_supervisor.health()
        self.assertEqual(health["restarts"], 1)
        self.assertTrue(health["ok"])

    def test_does_nothing_when_interface_is_up(self):
        apply = self._run_one_pass([True])
        apply.assert_not_called()
        self.assertEqual(awg_supervisor.health()["restarts"], 0)

    def test_reports_failure_when_reapply_did_not_help(self):
        apply = self._run_one_pass([False, False], apply_ok=False)
        apply.assert_called_once()
        health = awg_supervisor.health()
        self.assertFalse(health["ok"])
        self.assertIn("awg-quick", health["last_error"])


if __name__ == "__main__":
    unittest.main()
