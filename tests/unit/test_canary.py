"""
Канарейка: служебный пир не виден как клиент, панель заводит его только при
живом контейнере, пробы различают поломки по этапам.
"""
import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import bootstrap, canary, canary_probe, config_sync
from app.canary_probe import ProbeError
from app.database import Base
from app.models import Peer, ServerConfig
from app.routers import peers

RELAY_URL = ("vless://11111111-1111-1111-1111-111111111111@198.51.100.9:443"
             "?security=reality&sni=example.com&pbk=AAAA&sid=ab&fp=chrome&type=tcp#r")


class PanelSideTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        engine = create_engine(f"sqlite:///{self.tmp.name}/t.db")
        self.addCleanup(engine.dispose)
        Base.metadata.create_all(engine)
        self.db = sessionmaker(autoflush=False, bind=engine)()
        self.addCleanup(self.db.close)
        with mock.patch.object(bootstrap, "_detect_public_ip", return_value="203.0.113.1"):
            bootstrap.ensure_server_config(self.db)
        self.server = self.db.query(ServerConfig).first()
        self.server.cascade_enabled = True
        self.server.cascade_vless_url = RELAY_URL
        self.db.commit()

        d = Path(self.tmp.name) / "canary"
        d.mkdir()
        for name, value in (("CANARY_DIR", d), ("CONFIG_PATH", d / "config.json"),
                            ("RESULT_PATH", d / "result.json")):
            patcher = mock.patch.object(canary, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(config_sync, "apply_current_config")
        self.apply = patcher.start()
        self.addCleanup(patcher.stop)

    def _result(self, **extra):
        canary.RESULT_PATH.write_text(json.dumps({"ts": time.time(), **extra}), encoding="utf-8")

    def test_no_peer_without_sidecar(self):
        canary.sync(self.db)
        self.assertEqual(self.db.query(Peer).count(), 0)
        self.assertFalse(canary.CONFIG_PATH.exists())
        self.assertIsNone(canary.status()["ok"])

    def test_no_peer_with_cascade_off(self):
        self._result(state="idle")
        self.server.cascade_enabled = False
        self.db.commit()
        canary.sync(self.db)
        self.assertEqual(self.db.query(Peer).count(), 0)

    def test_sidecar_gets_peer_once_and_config(self):
        self._result(state="idle")
        canary.sync(self.db)
        canary.sync(self.db)
        self.assertEqual(self.db.query(Peer).filter(Peer.is_service.is_(True)).count(), 1)
        self.apply.assert_called_once()
        config = json.loads(canary.CONFIG_PATH.read_text(encoding="utf-8"))
        self.assertEqual(config["expected_exit_ips"], ["198.51.100.9"])
        self.assertIn("PrivateKey", config["conf"])
        self.assertEqual(canary.CONFIG_PATH.stat().st_mode & 0o777, 0o600)

    def test_config_removed_when_cascade_turned_off(self):
        self._result(state="idle")
        canary.sync(self.db)
        self.server.cascade_enabled = False
        self.db.commit()
        canary.sync(self.db)
        self.assertFalse(canary.CONFIG_PATH.exists())

    def test_service_peer_hidden_from_clients_api(self):
        self._result(state="idle")
        canary.sync(self.db)
        peer = canary.service_peer(self.db)
        with mock.patch.object(config_sync, "live_status_by_pubkey", return_value=None):
            self.assertEqual(peers.list_peers(db=self.db, _admin="admin"), [])
        for call in (peers.delete_peer, peers.read_peer, peers.regenerate_peer_keys):
            with self.assertRaises(peers.HTTPException):
                call(peer.id, db=self.db, _admin="admin")

    def test_status_reports_failure_and_stage(self):
        self._result(state="idle")
        canary.sync(self.db)
        self._result(state="probed", ok=False, stage="exit_ip", error="мимо", duration_ms=10)
        data = canary.status()
        self.assertIs(data["ok"], False)
        self.assertEqual(data["stage"], "exit_ip")

    def test_silent_sidecar_is_a_failure(self):
        self._result(state="idle")
        canary.sync(self.db)
        canary.RESULT_PATH.write_text(json.dumps(
            {"ts": time.time() - canary.STALE_AFTER_SECONDS - 1, "state": "probed", "ok": True}),
            encoding="utf-8")
        data = canary.status()
        self.assertIs(data["ok"], False)
        self.assertEqual(data["stage"], "stale")

    def test_expected_ip_override(self):
        with mock.patch.object(canary.settings, "canary_expected_exit_ip", "192.0.2.1, 192.0.2.2"):
            self.assertEqual(canary.expected_exit_ips(self.server), ["192.0.2.1", "192.0.2.2"])


class FakeDns(threading.Thread):
    def __init__(self, answers=1, rcode=0):
        super().__init__(daemon=True)
        self.answers, self.rcode = answers, rcode
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]

    def run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(1500)
            except OSError:
                return
            flags = (0x8180 | self.rcode).to_bytes(2, "big")
            count = self.answers.to_bytes(2, "big")
            self.sock.sendto(data[:2] + flags + data[4:6] + count + data[8:], addr)


class ProbeTests(unittest.TestCase):
    def _dns(self, **kwargs):
        server = FakeDns(**kwargs)
        server.start()
        self.addCleanup(server.sock.close)
        return server.port

    def test_dns_ok(self):
        canary_probe.check_dns("127.0.0.1", ["www.example.com"], port=self._dns())

    def test_dns_nxdomain(self):
        with self.assertRaises(ProbeError) as ctx:
            canary_probe.check_dns("127.0.0.1", ["nope.example"], port=self._dns(answers=0, rcode=3))
        self.assertEqual(ctx.exception.stage, "dns")

    def test_dns_silence(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            with self.assertRaises(ProbeError):
                canary_probe.check_dns("127.0.0.1", ["a.example"], timeout=0.1, port=sock.getsockname()[1])

    def test_trace_parsing(self):
        self.assertEqual(canary_probe.parse_trace_ip("fl=1\nip=198.51.100.9\nts=1\n"), "198.51.100.9")
        self.assertIsNone(canary_probe.parse_trace_ip("<html>"))

    def test_exit_ip_mismatch(self):
        done = mock.Mock(returncode=0, stdout="ip=203.0.113.1\n", stderr="")
        with mock.patch.object(canary_probe.subprocess, "run", return_value=done):
            self.assertEqual(canary_probe.check_exit_ip(["203.0.113.1"]), "203.0.113.1")
            with self.assertRaises(ProbeError) as ctx:
                canary_probe.check_exit_ip(["198.51.100.9"])
        self.assertEqual(ctx.exception.stage, "exit_ip")

    def _evaluate(self, code="200", size=1048576, seconds=1.0):
        return canary_probe.evaluate_download(code, size, seconds, expected_bytes=1048576,
                                              max_seconds=20, min_bps=65536)

    def test_download_thresholds(self):
        self.assertEqual(self._evaluate()[0], 1048576)
        for kwargs in ({"code": "500"}, {"size": 500}, {"seconds": 25.0}, {"seconds": 19.9, "size": 1000000}):
            with self.assertRaises(ProbeError, msg=kwargs):
                self._evaluate(**kwargs)

    def test_rate_limit_is_not_a_breakage(self):
        speed, note = self._evaluate(code="429", size=100)
        self.assertIsNone(speed)
        self.assertTrue(note)

    def test_stalled_download_is_reported(self):
        done = mock.Mock(returncode=28, stdout="200 16384 25.0", stderr="")
        with mock.patch.object(canary_probe.subprocess, "run", return_value=done):
            with self.assertRaises(ProbeError) as ctx:
                canary_probe.check_download()
        self.assertIn("16384", str(ctx.exception))

    def test_probe_stops_at_first_failure(self):
        with mock.patch.object(canary_probe, "check_handshake"), \
                mock.patch.object(canary_probe, "check_dns", side_effect=ProbeError("dns", "нет")), \
                mock.patch.object(canary_probe, "check_exit_ip") as exit_ip:
            result = canary_probe.probe({"dns": "1.1.1.1"})
        self.assertFalse(result["ok"])
        self.assertEqual(result["stage"], "dns")
        exit_ip.assert_not_called()

    def test_setconf_strips_quick_keys_and_rewrites_endpoint(self):
        text = canary_probe.setconf_text(
            "[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/32\nMTU = 1280\nDNS = 1.1.1.1\nJc = 3\n"
            "[Peer]\nPublicKey = p\nEndpoint = 203.0.113.1:443\nAllowedIPs = 0.0.0.0/0\n",
            "172.17.0.1", 443)
        for gone in ("Address", "MTU", "DNS", "203.0.113.1"):
            self.assertNotIn(gone, text)
        self.assertIn("Jc = 3", text)
        self.assertIn("Endpoint = 172.17.0.1:443", text)


if __name__ == "__main__":
    unittest.main()
