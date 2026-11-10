"""
Адрес подключения для каждого клиента: "" - как на сервере, "4" или "6" -
принудительно. Меняется только Endpoint этого клиента.
"""
import tempfile
import unittest
from unittest import mock

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import awg_config, bootstrap, config_sync
from app.database import Base
from app.models import ServerConfig
from app.routers import peers
from app.schemas import PeerCreate, PeerUpdate

V4 = "203.0.113.1"
V6 = "2a03:6f00:a::432b"


class _Peer:
    name = "n"
    public_key = "PUB="
    private_key = "PRIV="
    preshared_key = "PSK="
    address = "10.13.13.2/32"
    allowed_ips_client = "0.0.0.0/0, ::/0"
    dns_override = None
    persistent_keepalive = 25
    enabled = True
    endpoint_family = ""


class _Server:
    endpoint_host = V4
    endpoint_host_v6 = V6
    ip_family = "4"
    client_endpoint_host = ServerConfig.client_endpoint_host
    listen_port = 443

    def __getattr__(self, name):  # остальные поля конфига нам не важны
        return mock.MagicMock()


def _endpoint(peer_family, server_family="4", v6=V6):
    peer, server = _Peer(), _Server()
    peer.endpoint_family = peer_family
    server.ip_family = server_family
    server.endpoint_host_v6 = v6
    return awg_config._peer_endpoint_host(peer, server)


class EndpointChoiceTests(unittest.TestCase):
    def test_empty_follows_server_family(self):
        self.assertEqual(_endpoint("", "4"), V4)
        self.assertEqual(_endpoint("", "6"), V6)

    def test_peer_choice_overrides_server_family(self):
        self.assertEqual(_endpoint("6", "4"), V6)
        self.assertEqual(_endpoint("4", "6"), V4)

    def test_missing_v6_address_falls_back_to_server_choice(self):
        self.assertEqual(_endpoint("6", "4", v6=""), V4)

    def test_peer_without_the_attribute_is_treated_as_default(self):
        class _OldPeer:  # объект без поля, как двойники в других тестах
            pass
        peer = _OldPeer()
        self.assertEqual(awg_config._peer_endpoint_host(peer, _Server()), V4)


class RouterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        engine = create_engine(f"sqlite:///{self.tmp.name}/t.db",
                               connect_args={"check_same_thread": False})
        self.addCleanup(engine.dispose)
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.addCleanup(self.db.close)
        with mock.patch.object(bootstrap, "_detect_public_ip", return_value=V4), \
                mock.patch.object(bootstrap, "_detect_public_ipv6", return_value=""):
            bootstrap.ensure_server_config(self.db)
        for patch in (mock.patch.object(config_sync, "apply_current_config"),
                      mock.patch.object(config_sync, "live_status_by_pubkey", return_value={})):
            patch.start()
            self.addCleanup(patch.stop)

    def _server(self, v6=V6):
        server = config_sync.get_server(self.db)
        server.endpoint_host_v6 = v6
        self.db.add(server)
        self.db.commit()

    def _create(self, name="c", family=""):
        return peers.create_peer(PeerCreate(name=name, endpoint_family=family), self.db, "admin")

    def _endpoint_line(self, text):
        return next(l for l in text.splitlines() if l.startswith("Endpoint"))

    def test_default_is_server_family(self):
        self._server()
        created = self._create()
        self.assertEqual(created.endpoint_family, "")
        self.assertTrue(self._endpoint_line(created.config_text).startswith(f"Endpoint = {V4}:"))

    def test_create_with_ipv6(self):
        self._server()
        created = self._create(family="6")
        self.assertEqual(created.endpoint_family, "6")
        self.assertTrue(self._endpoint_line(created.config_text).startswith(f"Endpoint = [{V6}]:"))

    def test_other_clients_are_not_touched(self):
        self._server()
        first = self._create("a")
        self._create("b", family="6")
        again = peers.read_peer(first.id, self.db, "admin")
        self.assertTrue(self._endpoint_line(again.config_text).startswith(f"Endpoint = {V4}:"))

    def test_create_ipv6_without_server_address_is_rejected(self):
        self._server(v6="")
        with self.assertRaises(HTTPException) as ctx:
            self._create(family="6")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_update_switches_and_resets(self):
        self._server()
        peer = self._create()
        peers.update_peer(peer.id, PeerUpdate(endpoint_family="6"), self.db, "admin")
        text = peers.read_peer(peer.id, self.db, "admin").config_text
        self.assertTrue(self._endpoint_line(text).startswith(f"Endpoint = [{V6}]:"))
        peers.update_peer(peer.id, PeerUpdate(endpoint_family=""), self.db, "admin")
        text = peers.read_peer(peer.id, self.db, "admin").config_text
        self.assertTrue(self._endpoint_line(text).startswith(f"Endpoint = {V4}:"))

    def test_update_without_the_field_keeps_choice(self):
        self._server()
        peer = self._create(family="6")
        peers.update_peer(peer.id, PeerUpdate(note="x"), self.db, "admin")
        self.assertEqual(peers.read_peer(peer.id, self.db, "admin").endpoint_family, "6")

    def test_update_ipv6_without_server_address_is_rejected(self):
        self._server(v6="")
        peer = self._create()
        with self.assertRaises(HTTPException):
            peers.update_peer(peer.id, PeerUpdate(endpoint_family="6"), self.db, "admin")

    def test_unknown_family_is_rejected_by_schema(self):
        from pydantic import ValidationError
        with self.assertRaises(ValidationError):
            PeerCreate(name="x", endpoint_family="5")


if __name__ == "__main__":
    unittest.main()
