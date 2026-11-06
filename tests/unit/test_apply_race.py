"""
Параллельное применение конфига.

Двадцать одновременных созданий клиента: у каждого свой адрес, применения не
пересекаются, и последний применённый конфиг содержит всех.
"""
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import awg_manager, bootstrap, config_sync, fsutil
from app.awg_manager import CommandResult
from app.database import Base
from app.models import Peer
from app.routers import peers
from app.schemas import PeerCreate


class ParallelCreateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        engine = create_engine(
            f"sqlite:///{self.tmp.name}/t.db",
            connect_args={"check_same_thread": False, "timeout": 30},
        )
        self.addCleanup(engine.dispose)
        Base.metadata.create_all(engine)
        self.Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        db = self.Session()
        with mock.patch.object(bootstrap, "_detect_public_ip", return_value="203.0.113.1"):
            bootstrap.ensure_server_config(db)
        db.close()

        self.state = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.applied: list[str] = []

    def _fake_apply(self, _iface, text):
        with self.state:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        threading.Event().wait(0.005)
        with self.state:
            self.active -= 1
            self.applied.append(text)
        return CommandResult(True, "")

    def _create(self, number, errors):
        db = self.Session()
        try:
            peers.create_peer(PeerCreate(name=f"c{number}"), db, "admin")
        except Exception as exc:  # noqa: BLE001 - тест собирает любые сбои потоков
            errors.append(exc)
        finally:
            db.close()

    def test_twenty_parallel_creations(self):
        errors = []
        threads = [threading.Thread(target=self._create, args=(i, errors)) for i in range(20)]
        with mock.patch.object(config_sync.awg_manager, "apply", self._fake_apply), \
             mock.patch.object(config_sync.awg_manager, "tools_available", return_value=False), \
             mock.patch.object(config_sync.cascade, "sync", return_value=None), \
             mock.patch.object(config_sync, "_apply_tunnels"):
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(self.max_active, 1, "применения пересеклись")

        db = self.Session()
        rows = db.query(Peer).all()
        db.close()
        self.assertEqual(len(rows), 20)
        self.assertEqual(len({r.address for r in rows}), 20, "два клиента получили один адрес")
        self.assertEqual(awg_manager.expected_peers(self.applied[-1]), {r.public_key for r in rows})


class AtomicWriteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "awg0.conf"

    def test_writes_with_private_mode(self):
        fsutil.atomic_write(self.path, "new")
        self.assertEqual(self.path.read_text(), "new")
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_failure_keeps_old_file_and_leaves_no_temp(self):
        self.path.write_text("old")
        with mock.patch.object(fsutil.os, "replace", side_effect=OSError("диск")):
            with self.assertRaises(OSError):
                fsutil.atomic_write(self.path, "new")
        self.assertEqual(self.path.read_text(), "old")
        self.assertEqual(os.listdir(self.tmp.name), ["awg0.conf"])


class ReconcileTests(unittest.TestCase):
    CONFIG = "[Interface]\nPrivateKey = x\n\n[Peer]\nPublicKey = A=\n\n[Peer]\nPublicKey = B=\n"
    OK = CommandResult(True, "")

    def _reconcile(self, live, retry=OK, first=OK):
        sync = mock.Mock(return_value=retry)
        with mock.patch.object(awg_manager, "live_peers", side_effect=live), \
             mock.patch.object(awg_manager, "_syncconf", sync):
            return awg_manager._reconcile("awg0", Path("/x"), self.CONFIG, first), sync

    def test_match_needs_no_retry(self):
        result, sync = self._reconcile([{"A=", "B="}])
        self.assertTrue(result.ok)
        sync.assert_not_called()

    def test_single_retry_fixes_it(self):
        result, sync = self._reconcile([{"A="}, {"A=", "B="}])
        self.assertTrue(result.ok)
        sync.assert_called_once()

    def test_persistent_mismatch_is_an_error(self):
        result, sync = self._reconcile([{"A="}, {"A=", "C="}])
        self.assertFalse(result.ok)
        self.assertIn("не хватает 1", result.output)
        self.assertIn("лишних 1", result.output)
        sync.assert_called_once()

    def test_failed_apply_is_not_checked(self):
        bad = CommandResult(False, "сбой")
        result, sync = self._reconcile([], first=bad)
        self.assertIs(result, bad)
        sync.assert_not_called()


if __name__ == "__main__":
    unittest.main()
