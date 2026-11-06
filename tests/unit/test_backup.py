"""
Резервные копии data.

В архиве лежат ключи сервера и всех клиентов — потеря data без копии
означает переконфигурацию каждого клиента вручную. Тесты следят за тем,
что копия действительно собирается, не тянет саму себя и не разрастается
без предела.
"""
import os
import sqlite3
import tarfile
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data = Path(self.tmp.name)
        with sqlite3.connect(self.data / "awg_panel.db") as db:
            db.execute("create table t (id integer primary key, value text)")
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

    def restored(self, path):
        restore = Path(self.tmp.name) / "restored"
        with tarfile.open(path) as tar:
            tar.extractall(restore, filter="data")
        return restore

    def test_restores_under_continuous_writes(self):
        stop = threading.Event()

        def writer():
            db = sqlite3.connect(self.data / "awg_panel.db", timeout=30)
            while not stop.is_set():
                with db:
                    db.executemany("insert into t (value) values (?)", [("x" * 500,)] * 50)
                stop.wait(0.005)
            db.close()

        thread = threading.Thread(target=writer)
        thread.start()
        try:
            paths = [self.backup.create() for _ in range(5)]
        finally:
            stop.set()
            thread.join()
        counts = []
        for path in paths:
            restore = self.restored(path)
            db = sqlite3.connect(restore / "awg_panel.db")
            self.assertEqual(db.execute("pragma integrity_check").fetchall(), [("ok",)])
            counts.append(db.execute("select count(*) from t").fetchone()[0])
            db.close()
            self.assertEqual(counts[-1] % 50, 0, "снимок застал транзакцию на середине")
            self.assertFalse(list(restore.glob("*.db-*")))
        self.assertGreater(counts[-1], counts[0], "запись шла параллельно с копиями")

    def test_broken_database_gives_error_and_no_archive(self):
        with sqlite3.connect(self.data / "awg_panel.db") as db:
            db.executemany("insert into t (value) values (?)", [("x" * 500,)] * 500)
        with open(self.data / "awg_panel.db", "r+b") as raw:
            raw.seek(4096 * 2)
            raw.write(b"\xff" * 4096 * 3)
        self.addCleanup(self.backup._status.update, last_error=None, last_success_at=None)
        with self.assertRaises(self.backup.BackupError):
            self.backup.create()
        self.assertFalse(list((self.data / "backups").glob("noisefloor-*")))
        self.assertIn("awg_panel.db", self.backup.status()["last_error"])

    def test_error_clears_after_success(self):
        self.backup._status["last_error"] = "старая"
        self.addCleanup(self.backup._status.update, last_error=None, last_success_at=None)
        self.backup.create()
        self.assertIsNone(self.backup.status()["last_error"])
        self.assertIsNotNone(self.backup.status()["last_success_at"])

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
        self.assertTrue(first.exists(), "первая копия должна остаться на месте")
        with tarfile.open(second) as tar:
            self.assertNotIn("backups", tar.getnames())

    def test_same_millisecond_still_gives_distinct_names(self):
        # На быстрой машине (CI) две копии подряд укладываются в одну
        # миллисекунду — имя не может опираться только на часы.
        with mock.patch.object(self.backup, "_timestamp", return_value="20260913-081116-618"):
            names = {self.backup.create().name for _ in range(3)}
        self.assertEqual(len(names), 3)

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
