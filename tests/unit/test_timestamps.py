"""
Метки времени, уезжающие в API, обязаны нести часовой пояс.

SQLite зону не хранит: записанное как UTC читается обратно «голым». Строку
без зоны браузер понимает как МЕСТНОЕ время — и синхронизация, выполненная
секунду назад, показывалась как «3 часа назад» на UTC+3. Ошибка тем
неприятнее, что выглядит как враньё интерфейса, а не как поломка.
"""
import json
import unittest
from datetime import datetime, timedelta, timezone

from app.schemas import BackupInfo, CascadeStatus, LivePeerStatus, PeerRead, ServerRead


class NaiveDatetimeTests(unittest.TestCase):
    def test_cascade_status_marks_naive_time_as_utc(self):
        naive = datetime(2026, 9, 5, 15, 42, 30)
        status = CascadeStatus(
            enabled=True, configured=True, running=True, error=None,
            synced_at=naive, verified_at=naive,
        )
        self.assertEqual(status.synced_at.tzinfo, timezone.utc)
        self.assertEqual(status.verified_at.tzinfo, timezone.utc)

    def test_serialised_json_carries_timezone(self):
        """Именно этого не хватало: в JSON должна быть Z или смещение."""
        status = CascadeStatus(
            enabled=True, configured=True, running=True, error=None,
            synced_at=datetime(2026, 9, 5, 15, 42, 30),
        )
        rendered = json.loads(status.model_dump_json())["synced_at"]
        self.assertTrue(
            rendered.endswith("Z") or "+00:00" in rendered,
            f"время уехало без зоны: {rendered}",
        )

    def test_already_aware_time_is_left_alone(self):
        aware = datetime(2026, 9, 5, 15, 42, 30, tzinfo=timezone(timedelta(hours=3)))
        status = CascadeStatus(
            enabled=False, configured=False, running=False, error=None, synced_at=aware,
        )
        self.assertEqual(status.synced_at.utcoffset(), timedelta(hours=3))

    def test_none_stays_none(self):
        status = CascadeStatus(
            enabled=False, configured=False, running=False, error=None,
        )
        self.assertIsNone(status.synced_at)
        self.assertIsNone(status.verified_at)

    def test_peer_timestamps_carry_timezone(self):
        peer = PeerRead(
            id=1, name="Ноутбук", public_key="k", address="10.13.13.2/32",
            allowed_ips_client="0.0.0.0/0", dns_override=None,
            persistent_keepalive=25, enabled=True, note=None,
            created_at=datetime(2026, 9, 5, 10, 0, 0),
            latest_handshake=datetime(2026, 9, 5, 15, 0, 0),
        )
        self.assertEqual(peer.created_at.tzinfo, timezone.utc)
        self.assertEqual(peer.latest_handshake.tzinfo, timezone.utc)

    def test_live_peer_status_carries_timezone(self):
        live = LivePeerStatus(
            peer_id=1, name="Ноутбук", online=True, endpoint=None,
            latest_handshake=datetime(2026, 9, 5, 15, 0, 0),
            transfer_rx=0, transfer_tx=0,
        )
        self.assertEqual(live.latest_handshake.tzinfo, timezone.utc)

    def test_backup_timestamp_carries_timezone(self):
        info = BackupInfo(
            name="noisefloor-20260905-150000-000.tar.gz", size=1024,
            created_at=datetime(2026, 9, 5, 15, 0, 0), encrypted=False,
        )
        self.assertEqual(info.created_at.tzinfo, timezone.utc)

    def test_server_read_timestamps_carry_timezone(self):
        naive = datetime(2026, 9, 5, 15, 0, 0)
        server = ServerRead(
            id=1, interface_name="awg0", public_key="k", address="10.13.13.1/24",
            listen_port=443, dns="1.1.1.1", mtu=None, endpoint_host="example.com",
            egress_interface="eth0", cascade_enabled=False, cascade_vless_url="",
            cascade_last_error=None, cascade_synced_at=naive,
            jc=1, jmin=1, jmax=2, s1=0, s2=0, s3=0, s4=0,
            h1="1", h2="2", h3="3", h4="4", i1="", i2="", i3="", i4="", i5="",
            last_apply_status="ok", last_apply_error=None,
            last_applied_at=naive, updated_at=naive,
        )
        for field in (server.cascade_synced_at, server.last_applied_at, server.updated_at):
            self.assertEqual(field.tzinfo, timezone.utc)


if __name__ == "__main__":
    unittest.main()
