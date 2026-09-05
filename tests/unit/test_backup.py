"""
Резервные копии data.

В архиве лежат ключи сервера и всех клиентов — потеря data без копии
означает переконфигурацию каждого клиента вручную. Тесты следят за тем,
что копия действительно собирается, не тянет саму себя и не разрастается
без предела.
"""
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data = Path(self.tmp.name)
        (self.data / "awg_panel.db").write_text("база")
        (self.data / "secret_key").write_text("секрет")
        (self.data / "logs").mkdir()
        (self.data / "logs" / "xray.log").write_text("шум" * 1000)

        from app import backup
        self.backup = backup
        self._patches = [
            mock.patch.object(backup, "DATA_DIR", self.data),
            mock.patch.object(backup, "BACKUP_DIR", self.data / "backups"),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        self.tmp.cleanup()

    def test_archive_contains_keys_and_database(self):
        path = self.backup.create()
        with tarfile.open(path) as tar:
            names = tar.getnames()
        self.assertIn("awg_panel.db", names)
        self.assertIn("secret_key", names)

    def test_logs_and_backups_are_excluded(self):
        path = self.backup.create()
        with tarfile.open(path) as tar:
            names = tar.getnames()
        # Логи восстанавливать незачем, а вложить копии внутрь копии —
        # верный способ получить архив, растущий с каждым разом.
        self.assertNotIn("logs", names)
        self.assertNotIn("backups", names)

    def test_second_backup_does_not_swallow_the_first(self):
        first = self.backup.create()
        second = self.backup.create()
        self.assertNotEqual(first.name, second.name)
        with tarfile.open(second) as tar:
            self.assertNotIn("backups", tar.getnames())

    def test_retention_keeps_only_recent_copies(self):
        with mock.patch.object(self.backup, "KEEP_BACKUPS", 3):
            for _ in range(6):
                self.backup.create()
            kept = list((self.data / "backups").glob("noisefloor-*"))
        self.assertLessEqual(len(kept), 3)

    def test_archive_is_not_world_readable(self):
        path = self.backup.create()
        # Внутри приватные ключи: файл не должен читаться кем попало.
        self.assertEqual(oct(path.stat().st_mode & 0o077), "0o0")

    def test_listing_reports_newest_first(self):
        self.backup.create()
        self.backup.create()
        items = self.backup.listing()
        self.assertEqual(len(items), 2)
        self.assertGreaterEqual(items[0]["created_at"], items[1]["created_at"])

    def test_encrypted_when_passphrase_set(self):
        with mock.patch.dict(os.environ, {"BACKUP_PASSPHRASE": "секретная-фраза"}):
            path = self.backup.create()
        self.assertTrue(path.name.endswith(".enc"))
        # Зашифрованный архив не должен открываться как обычный tar.
        with self.assertRaises(tarfile.ReadError):
            tarfile.open(path)


if __name__ == "__main__":
    unittest.main()
