"""
VLESS Reality как самостоятельный протокол: свой xray без каскада, переезд входа
между процессами, клиенты VLESS через API.
"""
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import cascade, config_sync, fallback, vless_server
from app.database import Base
from app.models import FallbackClient, ServerConfig
from app.routers import fallback as fallback_router

FB = {"port": 8443, "sni": "dl.google.com", "dest": "dl.google.com:443", "private_key": "EXAMPLEkey",
      "short_id": "ab", "clients": ["00000000-0000-4000-8000-0000000000ff"]}
NO_CASCADE = SimpleNamespace(cascade_enabled=False, cascade_vless_url="", relays=[])
WITH_CASCADE = SimpleNamespace(cascade_enabled=True, cascade_vless_url="vless://x@example.com:443", relays=[])


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.config = vless_server.build_config(FB)

    def test_same_inbound_as_in_cascade(self):
        # Ссылки клиентов не должны зависеть от того, в каком процессе вход.
        self.assertEqual(self.config["inbounds"], [cascade._fallback_inbound(FB)])

    def test_default_route_is_direct(self):
        self.assertEqual(self.config["outbounds"][0]["tag"], "direct")
        self.assertEqual(self.config["routing"]["rules"][-1]["outboundTag"], "direct")

    def test_private_addresses_blocked_even_by_name(self):
        rules = self.config["routing"]["rules"]
        self.assertEqual(rules[0]["outboundTag"], "block")
        self.assertIn("127.0.0.0/8", rules[0]["ip"])
        self.assertIn("full:localhost", rules[1]["domain"])
        # Без разрешения имени ip-правило не видело бы, куда ведёт имя.
        self.assertEqual(self.config["routing"]["domainStrategy"], "IPOnDemand")

    def test_no_cascade_parts(self):
        tags = {o["tag"] for o in self.config["outbounds"]}
        self.assertNotIn(cascade.RELAY_TAG, tags)
        self.assertEqual(len(self.config["inbounds"]), 1)


class CascadeWantedTests(unittest.TestCase):
    def test_follows_cascade_switch_and_links(self):
        self.assertFalse(vless_server.cascade_wanted(NO_CASCADE))
        self.assertTrue(vless_server.cascade_wanted(WITH_CASCADE))
        self.assertFalse(vless_server.cascade_wanted(
            SimpleNamespace(cascade_enabled=True, cascade_vless_url="", relays=[])))


class SyncTests(unittest.TestCase):
    """Настоящий дочерний процесс: вместо xray скрипт, который просто ждёт."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        fake = Path(tmp.name) / "xray"
        fake.write_text("#!/bin/sh\nexec sleep 30\n")
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        for name, value in (("CONFIG_PATH", Path(tmp.name) / "c.json"), ("LOG_PATH", Path(tmp.name) / "x.log")):
            patcher = mock.patch.object(vless_server, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for patcher in (mock.patch.object(cascade, "XRAY_BIN", str(fake)),
                        mock.patch.object(fallback, "port_free", return_value=True)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(vless_server.stop)

    def sync(self, server=NO_CASCADE, params=FB):
        with mock.patch.object(fallback, "params", return_value=params):
            return vless_server.sync(server)

    def test_starts_without_cascade(self):
        self.assertIsNone(self.sync())
        self.assertTrue(vless_server.is_running())
        self.assertEqual(vless_server.listening_port(), 8443)
        self.assertTrue(vless_server.CONFIG_PATH.exists())
        self.assertEqual(stat.S_IMODE(os.stat(vless_server.CONFIG_PATH).st_mode), 0o600)

    def test_gives_way_to_cascade(self):
        self.sync()
        self.assertIsNone(self.sync(WITH_CASCADE))
        self.assertFalse(vless_server.is_running())

    def test_stops_when_turned_off(self):
        self.sync()
        self.sync(params=None)
        self.assertFalse(vless_server.is_running())
        self.assertFalse(vless_server._wanted)

    def test_unchanged_config_keeps_process(self):
        # Перезапуск рвёт соединения всех клиентов VLESS.
        self.sync()
        pid = vless_server._proc.pid
        self.sync()
        self.assertEqual(vless_server._proc.pid, pid)

    def test_new_client_restarts(self):
        self.sync()
        pid = vless_server._proc.pid
        self.sync(params={**FB, "clients": [*FB["clients"], "00000000-0000-4000-8000-0000000000fe"]})
        self.assertNotEqual(vless_server._proc.pid, pid)

    def test_busy_port_is_reported_and_not_retried(self):
        with mock.patch.object(fallback, "port_free", return_value=False):
            error = self.sync()
        self.assertIn("8443", error)
        self.assertEqual(vless_server.warning(), error)
        self.assertFalse(vless_server.is_running())
        # Иначе сторож перезапускал бы его вечно.
        self.assertFalse(vless_server._wanted)

    def test_own_port_is_not_busy(self):
        self.sync()
        with mock.patch.object(fallback, "port_free", return_value=False):
            self.assertIsNone(self.sync(params={**FB, "sni": "example.com"}))
        self.assertTrue(vless_server.is_running())

    def test_missing_xray(self):
        with mock.patch.object(cascade, "XRAY_BIN", "/nonexistent/xray"):
            self.assertIn("xray", self.sync())
        self.assertFalse(vless_server.is_running())


class ApplyOrderTests(unittest.TestCase):
    """Порт один: процесс, который его держит, обязан отпустить первым."""

    def order(self, server):
        calls = []
        with mock.patch.object(vless_server, "stop", side_effect=lambda: calls.append("vless.stop")), \
                mock.patch.object(vless_server, "sync", side_effect=lambda s: calls.append("vless.sync")), \
                mock.patch.object(cascade, "sync", side_effect=lambda s: calls.append("cascade.sync")), \
                mock.patch.object(config_sync, "get_server", return_value=server), \
                mock.patch.object(config_sync, "interface_names", side_effect=RuntimeError("стоп")):
            db = mock.MagicMock()
            db.query.return_value.all.return_value = []
            with self.assertRaises(RuntimeError):
                config_sync._apply_locked(db, restart=False, restart_tunnels=frozenset())
        return calls

    def test_cascade_on(self):
        self.assertEqual(self.order(WITH_CASCADE), ["vless.stop", "cascade.sync", "vless.sync"])

    def test_cascade_off(self):
        self.assertEqual(self.order(NO_CASCADE), ["cascade.sync", "vless.sync"])


class RouterTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.addCleanup(self.db.close)
        self.db.add(ServerConfig(private_key="a", public_key="b", endpoint_host="203.0.113.1"))
        self.db.commit()
        patcher = mock.patch.object(config_sync, "apply_current_config")
        self.apply = patcher.start()
        self.addCleanup(patcher.stop)

    def test_mode_without_cascade(self):
        with mock.patch.object(vless_server, "listening_port", return_value=443), \
                mock.patch.object(vless_server, "warning", return_value=None):
            data = fallback_router.get_settings(db=self.db, _admin="admin")
        self.assertEqual(data.mode, "direct")
        self.assertTrue(data.listening)

    def test_mode_with_cascade(self):
        server = config_sync.get_server(self.db)
        server.cascade_enabled, server.cascade_vless_url = True, "vless://x@example.com:443"
        self.db.commit()
        with mock.patch.object(cascade, "fallback_listening", return_value=False), \
                mock.patch.object(cascade, "fallback_warning", return_value="занят"):
            data = fallback_router.get_settings(db=self.db, _admin="admin")
        self.assertEqual((data.mode, data.listening, data.warning), ("cascade", False, "занят"))

    def test_read_client_has_link(self):
        created = fallback_router.create_client(fallback_router.FallbackClientCreate(name="Телефон"),
                                                db=self.db, _admin="admin")
        read = fallback_router.read_client(created.id, db=self.db, _admin="admin")
        self.assertEqual(read.link, created.link)
        self.assertIn("@203.0.113.1:", read.link)
        self.assertIsNotNone(read.created_at)

    def test_regenerate_changes_uuid_and_applies(self):
        created = fallback_router.create_client(fallback_router.FallbackClientCreate(name="a"),
                                                db=self.db, _admin="admin")
        old_uuid = self.db.get(FallbackClient, created.id).uuid
        self.apply.reset_mock()
        renewed = fallback_router.regenerate_client(created.id, db=self.db, _admin="admin")
        new_uuid = self.db.get(FallbackClient, created.id).uuid
        self.assertNotEqual(old_uuid, new_uuid)
        self.assertIn(new_uuid, renewed.link)
        self.apply.assert_called_once()


if __name__ == "__main__":
    unittest.main()
