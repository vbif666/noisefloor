"""Выделение адресов клиентам из подсети туннеля."""
import unittest

from app.ip_pool import next_available_ip


class IpPoolTests(unittest.TestCase):
    def test_first_client_gets_second_address(self):
        self.assertEqual(next_available_ip("10.13.13.1/24", {"10.13.13.1"}), "10.13.13.2/32")

    def test_skips_occupied_addresses(self):
        used = {"10.13.13.1", "10.13.13.2", "10.13.13.3"}
        self.assertEqual(next_available_ip("10.13.13.1/24", used), "10.13.13.4/32")

    def test_reuses_gap_left_by_deleted_peer(self):
        used = {"10.13.13.1", "10.13.13.2", "10.13.13.4"}
        self.assertEqual(next_available_ip("10.13.13.1/24", used), "10.13.13.3/32")

    def test_raises_with_actionable_message_when_exhausted(self):
        used = {f"10.13.13.{i}" for i in range(1, 255)}
        with self.assertRaises(ValueError) as ctx:
            next_available_ip("10.13.13.1/24", used)
        # Сообщение читает администратор в UI — оно должно подсказывать выход.
        self.assertIn("/22", str(ctx.exception))

    def test_respects_narrow_subnet(self):
        # /30 — сеть на две машины: .1 сервер, .2 единственный клиент.
        self.assertEqual(next_available_ip("10.9.0.1/30", {"10.9.0.1"}), "10.9.0.2/32")
        with self.assertRaises(ValueError):
            next_available_ip("10.9.0.1/30", {"10.9.0.1", "10.9.0.2"})


if __name__ == "__main__":
    unittest.main()
