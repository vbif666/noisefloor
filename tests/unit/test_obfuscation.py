"""
Профиль обфускации AmneziaWG.

H1-H4 обязаны отличаться друг от друга: это magic-значения, которыми
подменяется байт типа пакета. Совпадение двух из них делает два типа
пакетов неразличимыми и ломает хендшейк.
"""
import unittest

from app import obfuscation


class HeadersTests(unittest.TestCase):
    def test_four_distinct_values_every_time(self):
        for _ in range(200):
            headers = obfuscation.random_headers()
            self.assertEqual(len(headers), 4)
            self.assertEqual(len(set(headers)), 4, f"H1-H4 пересеклись: {headers}")

    def test_values_avoid_reserved_low_numbers(self):
        # 0 означает "выключено", 1-4 зарезервированы под типы пакетов WireGuard.
        for _ in range(200):
            for value in obfuscation.random_headers():
                self.assertGreater(int(value), 4)

    def test_values_fit_uint32(self):
        for _ in range(200):
            for value in obfuscation.random_headers():
                self.assertLess(int(value), 2**32)


class JunkTests(unittest.TestCase):
    def test_junk_sizes_stay_below_mtu(self):
        # Мусорные пакеты крупнее MTU фрагментируются — а фрагментация как раз
        # и демаскирует трафик, ради маскировки которого они и нужны.
        for _ in range(200):
            jc, jmin, jmax = obfuscation.random_junk()
            self.assertGreaterEqual(jc, 1)
            self.assertLess(jmin, jmax)
            self.assertLess(jmax, 1280)


if __name__ == "__main__":
    unittest.main()
