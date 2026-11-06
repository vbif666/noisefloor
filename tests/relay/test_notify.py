"""
Релей сообщает, что панель молчит.
"""
import unittest

import notify


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class PanelWatchTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.watch = notify.PanelWatch(900, clock=self.clock)

    def test_never_seen_panel_is_not_an_alarm(self):
        self.clock.now += 100000
        self.assertIsNone(self.watch.message())

    def test_alert_once_and_recovery(self):
        self.watch.seen()
        self.clock.now += 899
        self.assertIsNone(self.watch.message())
        self.clock.now += 1
        self.assertIn("15 мин", self.watch.message())
        self.watch.sent()
        self.clock.now += 1000
        self.assertIsNone(self.watch.message(), "одно сообщение на один простой")
        self.watch.seen()
        self.assertIn("снова на связи", self.watch.message())
        self.watch.sent()
        self.assertIsNone(self.watch.message())

    def test_unsent_alert_repeats(self):
        self.watch.seen()
        self.clock.now += 1000
        self.assertIsNotNone(self.watch.message())
        self.assertIsNotNone(self.watch.message(), "sent() не вызван, отправка не удалась")

    def test_disabled_by_default(self):
        self.assertFalse(notify.enabled())


if __name__ == "__main__":
    unittest.main()
