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
    cascade_enabled = False
    cascade_vless_url = ""
    cascade_sync_url = ""
    cascade_sync_token = ""
    jc = 5
    s1, s2, s3, s4 = 20, 30, 40, 12
    header_protection_key = "HPK="


class _Tunnel:
    def __init__(self, protocol, port):
        self.protocol = protocol
        self.listen_port = port


def _save(server=None, **changes):
    server = server or _Server()
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
