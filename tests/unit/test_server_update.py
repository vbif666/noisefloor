"""
Сохранение настроек сервера: перезапуск туннеля только когда он нужен.

Раньше каждое сохранение, даже смена токена релея или DNS, перезапускало
awg0 — все клиенты отваливались на несколько секунд. Перезапуск нужен лишь
для полей, которые `awg syncconf` не применяет на лету.
"""
import unittest
from unittest import mock

from app.routers import server as server_router
from app.schemas import ServerUpdate


class _Server:
    listen_port = 443
    address = "10.13.13.1/24"
    mtu = 1420
    dns = "1.1.1.1"
    endpoint_host = "1.2.3.4"
    endpoint_host_v6 = ""
    ip_family = "4"
    cascade_enabled = False
    cascade_vless_url = ""
    cascade_sync_url = ""
    cascade_sync_token = ""
    cascade_sync_error = None
    cascade_synced_at = None
    cascade_relay_version = None
    cascade_sync_cert_pin = ""
    jc = 5
    s1, s2, s3, s4 = 20, 30, 40, 12
    header_protection_key = "HPK="


class _Tunnel:
    def __init__(self, protocol, port):
        self.protocol = protocol
        self.listen_port = port


def _save(server=None, **changes):
    server = server or _Server()
    server.relays = []
    with mock.patch.object(server_router.config_sync, "get_server", return_value=server), \
         mock.patch.object(server_router.config_sync, "get_tunnels",
                           return_value=[_Tunnel("awg1", 51821), _Tunnel("wg", 51822)]), \
         mock.patch.object(server_router.config_sync, "apply_current_config") as apply:
        server_router.update_server(ServerUpdate(**changes), db=mock.MagicMock(), _admin="admin")
    return apply.call_args.kwargs


class RestartTests(unittest.TestCase):
    def test_client_only_fields_apply_without_restart(self):
        for changes in ({"dns": "8.8.8.8"}, {"endpoint_host": "vpn.example.com"},
                        {"cascade_sync_token": "t"}, {"cascade_enabled": True}):
            with self.subTest(changes=changes):
                kwargs = _save(**changes)
                self.assertFalse(kwargs["restart"])
                self.assertEqual(kwargs["restart_tunnels"], frozenset())

    def test_interface_fields_restart(self):
        for changes in ({"listen_port": 8443}, {"address": "10.13.20.1/24"}, {"jc": 9}):
            with self.subTest(changes=changes):
                self.assertTrue(_save(**changes)["restart"])

    def test_unchanged_value_does_not_restart(self):
        self.assertFalse(_save(listen_port=443)["restart"])

    def test_mtu_restarts_extra_protocols_too(self):
        kwargs = _save(mtu=1380)
        self.assertTrue(kwargs["restart"])
        self.assertEqual(kwargs["restart_tunnels"], frozenset({"awg1", "wg"}))

    def test_js_restart_list_matches_server(self):
        # Интерфейс заранее предупреждает о перезапуске по своему списку —
        # он обязан совпадать с серверным, иначе предупреждение соврёт.
        import pathlib
        import re
        here = pathlib.Path(__file__).resolve()
        js = next((p / "amneziawg-panel/src/static/app.js" for p in here.parents
                   if (p / "amneziawg-panel/src/static/app.js").exists()), None)
        if js is None:
            self.skipTest("app.js не примонтирован")
        rows = re.findall(r'\["(\w+)", "f-[\w-]+", "[^"]+", (true|false),', js.read_text(encoding="utf-8"))
        js_restart = {field for field, flag in rows if flag == "true"}
        self.assertTrue(js_restart)
        self.assertLessEqual(js_restart, server_router.RESTART_FIELDS)
        editable = {field for field, _ in rows}
        self.assertEqual(js_restart, server_router.RESTART_FIELDS & editable)



class HeaderProtectionPaddingTests(unittest.TestCase):
    """С ключом 3.1 amneziawg-go не поднимет интерфейс при S меньше 12 —
    такое сохранение отклоняется ещё схемой, а не роняет туннель."""

    def test_small_padding_rejected(self):
        from pydantic import ValidationError
        for field in ("s1", "s2", "s3", "s4"):
            with self.subTest(field=field), self.assertRaises(ValidationError):
                ServerUpdate(**{field: 11})

    def test_floor_value_accepted(self):
        self.assertTrue(_save(s2=12)["restart"])


class IpFamilyTests(unittest.TestCase):
    V6 = "2a03:6f00:a::432b"

    def _save_with_sync(self, server=None, **changes):
        server = server or _Server()
        with mock.patch.object(server_router.cascade_sync, "sync_once") as sync:
            kwargs = _save(server, **changes)
        return server, sync, kwargs

    def test_switch_to_v6_without_address_is_rejected(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            _save(ip_family="6")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_switch_with_address_in_same_request(self):
        server, _, _ = self._save_with_sync(endpoint_host_v6=self.V6, ip_family="6")
        self.assertEqual((server.ip_family, server.endpoint_host_v6), ("6", self.V6))

    def test_switch_with_stored_address(self):
        server = _Server()
        server.endpoint_host_v6 = self.V6
        server, _, _ = self._save_with_sync(server, ip_family="6")
        self.assertEqual(server.ip_family, "6")

    def test_ipv4_in_v6_field_is_rejected(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException):
            _save(endpoint_host_v6="203.0.113.5")

    def test_brackets_are_stripped(self):
        server, _, _ = self._save_with_sync(endpoint_host_v6=f"[{self.V6}]")
        self.assertEqual(server.endpoint_host_v6, self.V6)

    def test_unknown_family_is_rejected_by_schema(self):
        from pydantic import ValidationError
        with self.assertRaises(ValidationError):
            ServerUpdate(ip_family="5")

    def test_family_change_resyncs_cascade_once(self):
        server = _Server()
        server.cascade_enabled = True
        server.endpoint_host_v6 = self.V6
        _, sync, _ = self._save_with_sync(server, ip_family="6")
        sync.assert_called_once()

    def test_family_change_without_cascade_does_not_sync(self):
        server = _Server()
        server.endpoint_host_v6 = self.V6
        _, sync, _ = self._save_with_sync(server, ip_family="6")
        sync.assert_not_called()

    def test_family_change_needs_no_tunnel_restart(self):
        server = _Server()
        server.endpoint_host_v6 = self.V6
        _, _, kwargs = self._save_with_sync(server, ip_family="6")
        self.assertFalse(kwargs["restart"])
