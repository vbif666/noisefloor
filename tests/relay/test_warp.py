"""
Выход через Cloudflare WARP: регистрация, конфиг xray, проверка живости.

Сеть не нужна: API Cloudflare и вход проверки подменяются. Единственное
исключение - проверка конфига настоящим xray, если он есть в образе.
"""
import base64
import json
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="relay-test-"))
os.environ.setdefault("ADMIN_PASSWORD", "test")

import app  # noqa: E402
from test_config_apply import NOW, Base, make_creds  # noqa: E402

# Ответ /reg в том виде, в каком его отдал API 2026-11-07 (без "result").
REG = {
    "id": "3e3f1ccc-9513-468b-a6df-31359b13a486",
    "token": "tok",
    "account": {"account_type": "free"},
    "config": {
        "client_id": "RWRv",
        "peers": [{
            "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            "endpoint": {"v4": "162.159.192.10:0", "v6": "[2606:4700:d0::a29f:c00a]:0",
                         "host": "engage.cloudflareclient.com:2408"},
        }],
        "interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700:110:80b8::1"}},
    },
}
# Настоящая пара WireGuard, чтобы xray -test принял конфиг.
PRIV = "mBGKpkzoiFgKAkdNbVHDSw5NVOB1aYUUZnjdOUBaaW0="


def account():
    return app.parse_warp_registration(REG, PRIV)


def warp_creds(**warp):
    creds = make_creds()
    creds["warp"] = {**app.warp_defaults(), "enabled": True, "account": account(), **warp}
    return creds


class RegistrationTests(unittest.TestCase):
    def test_parses_current_api(self):
        acc = account()
        self.assertEqual(acc["endpoint"], "162.159.192.10:2408")
        self.assertEqual(acc["reserved"], list(base64.b64decode("RWRv")))
        self.assertEqual(acc["address_v4"], "172.16.0.2")
        self.assertEqual(acc["account_type"], "free")

    def test_parses_wrapped_result(self):
        self.assertEqual(app.parse_warp_registration({"result": REG}, PRIV)["id"], REG["id"])

    def test_endpoint_falls_back_to_host(self):
        peer = {"endpoint": {"v4": "", "host": "engage.cloudflareclient.com:2408"}}
        self.assertEqual(app._warp_endpoint(peer), "engage.cloudflareclient.com:2408")
        self.assertEqual(app._warp_endpoint({}), app.WARP_DEFAULT_ENDPOINT)

    def test_bad_client_id_gives_zero_reserved(self):
        reg = json.loads(json.dumps(REG))
        reg["config"]["client_id"] = ""
        self.assertEqual(app.parse_warp_registration(reg, PRIV)["reserved"], [0, 0, 0])

    def test_wg_keys_parsed_from_xray_output(self):
        out = ("PrivateKey: " + PRIV + "\nPassword (PublicKey): FMcUxio01pprpG/JLb8IjVH4wlfGGyaA540mB0g87Gk=\n"
               "Hash32: AmFyFTTIDXJb1nfv2kUxiOSX2ULPsfSEy7vEcUI8sMA=\n")
        with mock.patch.object(app.subprocess, "run", return_value=mock.Mock(stdout=out)) as run:
            keys = app.run_wg_keys()
        self.assertEqual(run.call_args[0][0][1], "wg")
        self.assertEqual(keys["private_key"], PRIV)
        self.assertTrue(keys["public_key"].startswith("FMcU"))

    def test_register_sends_public_key(self):
        keys = {"private_key": PRIV, "public_key": "PUB"}
        with mock.patch.object(app, "run_wg_keys", return_value=keys), \
             mock.patch.object(app, "_warp_request", return_value=REG) as req:
            acc = app.warp_register()
        self.assertEqual(req.call_args[0][:2], ("POST", "/reg"))
        self.assertEqual(req.call_args[0][2]["key"], "PUB")
        self.assertEqual(acc["private_key"], PRIV)


class XrayPartsTests(unittest.TestCase):
    def rules(self, creds):
        return app.build_config(creds, NOW)["routing"]["rules"]

    def test_not_connected_changes_nothing(self):
        creds = make_creds()
        self.assertEqual(app.warp_xray_parts(creds), ([], [], []))
        creds["warp"] = dict(app.warp_defaults(), enabled=True)  # без аккаунта
        self.assertEqual(app.warp_xray_parts(creds), ([], [], []))

    def test_healthy_routes_domains(self):
        cfg = app.build_config(warp_creds(), NOW)
        out = next(o for o in cfg["outbounds"] if o["tag"] == "warp")
        self.assertEqual(out["settings"]["peers"][0]["endpoint"], "162.159.192.10:2408")
        self.assertEqual(out["settings"]["mtu"], app.WARP_MTU)
        rule = next(r for r in cfg["routing"]["rules"] if r.get("domain"))
        self.assertEqual(rule["outboundTag"], "warp")
        self.assertIn("domain:chatgpt.com", rule["domain"])
        self.assertEqual(len(rule["domain"]), 10)
        probe = next(i for i in cfg["inbounds"] if i["tag"] == "warp-probe")
        self.assertEqual(probe["listen"], "127.0.0.1")

    def test_unhealthy_keeps_only_probe(self):
        rules = self.rules(warp_creds(healthy=False))
        self.assertFalse([r for r in rules if r.get("domain")])
        self.assertTrue([r for r in rules if r.get("inboundTag") == ["warp-probe"]])

    def test_disabled_removes_everything(self):
        cfg = app.build_config(warp_creds(enabled=False), NOW)
        self.assertFalse([o for o in cfg["outbounds"] if o["tag"] == "warp"])

    def test_dns_through_warp(self):
        cfg = app.build_config(warp_creds(), NOW)
        self.assertEqual(cfg["dns"]["servers"][0], "https://1.1.1.1/dns-query")
        rule = next(r for r in cfg["routing"]["rules"] if r.get("inboundTag") == [app.WARP_DNS_TAG])
        self.assertEqual(rule["outboundTag"], "warp")
        direct = next(o for o in cfg["outbounds"] if o["tag"] == "direct")
        self.assertEqual(direct["settings"]["domainStrategy"], "UseIP")
        rules = cfg["routing"]["rules"]
        hijack = next(i for i, r in enumerate(rules) if r["outboundTag"] == "dns-hijack")
        self.assertEqual(rules[hijack]["port"], 53)
        first_domain = next(i for i, r in enumerate(rules) if r.get("domain"))
        self.assertLess(hijack, first_domain)

    def test_dns_goes_direct_while_unhealthy(self):
        cfg = app.build_config(warp_creds(healthy=False), NOW)
        rule = next(r for r in cfg["routing"]["rules"] if r.get("inboundTag") == [app.WARP_DNS_TAG])
        self.assertEqual(rule["outboundTag"], "direct")

    def test_dns_off_keeps_system_resolver(self):
        cfg = app.build_config(warp_creds(dns=False), NOW)
        self.assertNotIn("dns", cfg)
        direct = next(o for o in cfg["outbounds"] if o["tag"] == "direct")
        self.assertNotIn("settings", direct)
        self.assertNotIn("dns", app.build_config(make_creds(), NOW))

    @unittest.skipUnless(Path(app.XRAY_BIN).exists(), "xray нет в окружении")
    def test_real_xray_accepts_config(self):
        creds = warp_creds()
        creds.update(private_key=PRIV.rstrip("="), short_id="0123abcd")  # make_creds держит заглушки; REALITY ждёт base64url без "="
        path = Path(app.DATA_DIR) / "warp-test-config.json"
        path.write_text(json.dumps(app.build_config(creds, NOW)))
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        self.assertIsNone(app._xray_test(path))


class CheckTests(Base):
    def setUp(self):
        super().setUp()
        self.creds = warp_creds()
        app.save_creds(self.creds)
        self.run_with(self.creds)

    def test_ok_keeps_process(self):
        with mock.patch.object(app, "warp_probe", return_value={"ip": "104.28.0.1", "loc": "NL", "warp": "on"}):
            w = app.warp_check()
        self.assertTrue(w["healthy"])
        self.assertEqual(w["exit_ip"], "104.28.0.1 (NL)")
        self.restart.assert_not_called()

    def test_single_failure_keeps_routes(self):
        with mock.patch.object(app, "warp_probe", side_effect=OSError("таймаут")):
            w = app.warp_check()
        self.assertTrue(w["healthy"])
        self.assertEqual(w["fails"], 1)
        self.assertIn("таймаут", w["last_error"])
        self.restart.assert_not_called()

    def test_failures_drop_routes_then_recover(self):
        with mock.patch.object(app, "warp_probe", side_effect=OSError("таймаут")):
            for _ in range(app.WARP_FAIL_LIMIT):
                w = app.warp_check()
        self.assertFalse(w["healthy"])
        self.restart.assert_called_once()
        self.assertEqual(app.warp_route_domains(app.load_creds()), [])
        with mock.patch.object(app, "warp_probe", return_value={"ip": "1.1.1.1", "loc": "NL", "warp": "on"}):
            w = app.warp_check()
        self.assertTrue(w["healthy"])
        self.assertEqual(self.restart.call_count, 2)
        self.assertEqual(len(app.warp_route_domains(app.load_creds())), 10)


class FakeSocks:
    """Минимальный SOCKS5: принимает CONNECT и отдаёт заданный trace."""

    def __init__(self, trace: str):
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.port = self.srv.getsockname()[1]
        self.trace = trace
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        conn, _ = self.srv.accept()
        with conn:
            conn.recv(3)
            conn.sendall(b"\x05\x00")
            head = conn.recv(5)
            conn.recv(head[4] + 2)
            conn.sendall(b"\x05\x00\x00\x01" + bytes(4) + b"\x00\x50")
            conn.recv(4096)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + self.trace.encode())
        self.srv.close()


class ProbeTests(unittest.TestCase):
    def test_reads_trace(self):
        srv = FakeSocks("fl=1\nip=104.28.219.140\nloc=NL\nwarp=on\n")
        info = app.warp_probe(port=srv.port, timeout=5)
        self.assertEqual(info, {"ip": "104.28.219.140", "loc": "NL", "warp": "on"})

    def test_warp_off_is_failure(self):
        srv = FakeSocks("ip=37.220.85.109\nloc=NL\nwarp=off\n")
        with self.assertRaises(ConnectionError):
            app.warp_probe(port=srv.port, timeout=5)


class ApiTests(Base):
    def setUp(self):
        super().setUp()
        from fastapi.testclient import TestClient
        self.creds = make_creds()
        app.save_creds(self.creds)
        self.run_with(self.creds)
        app.app.dependency_overrides[app.check_auth] = lambda: None
        self.addCleanup(app.app.dependency_overrides.clear)
        self.c = TestClient(app.app, base_url="https://testserver", follow_redirects=False)

    def test_connect_enables_and_hides_secrets(self):
        with mock.patch.object(app, "warp_register", return_value=account()):
            r = self.c.post("/api/warp/connect")
        self.assertEqual(r.status_code, 200)
        w = app.get_warp(app.load_creds())
        self.assertTrue(w["enabled"])
        self.assertEqual(w["account"]["private_key"], PRIV)
        self.restart.assert_called_once()
        status = self.c.get("/api/warp").json()
        self.assertTrue(status["connected"])
        self.assertNotIn(PRIV, json.dumps(status))
        self.assertNotIn("tok", json.dumps(status))

    def test_connect_failure_reports(self):
        with mock.patch.object(app, "warp_register", side_effect=OSError("нет сети")):
            r = self.c.post("/api/warp/connect")
        self.assertEqual(r.status_code, 502)
        self.assertIn("нет сети", r.json()["detail"])
        self.assertIsNone(app.get_warp(app.load_creds())["account"])

    def test_save_domains(self):
        with mock.patch.object(app, "warp_register", return_value=account()):
            self.c.post("/api/warp/connect")
        r = self.c.post("/api/warp", data={"enabled": "on", "domains": "https://x.example/path\n*.y.example\n"})
        self.assertEqual(r.status_code, 303)
        self.assertEqual(app.get_warp(app.load_creds())["domains"], ["x.example", "y.example"])

    def test_disconnect_unregisters_and_keeps_domains(self):
        with mock.patch.object(app, "warp_register", return_value=account()):
            self.c.post("/api/warp/connect")
        self.c.post("/api/warp", data={"enabled": "on", "domains": "x.example"})
        with mock.patch.object(app, "warp_unregister") as unreg:
            self.c.post("/api/warp/disconnect")
        unreg.assert_called_once()
        w = app.get_warp(app.load_creds())
        self.assertIsNone(w["account"])
        self.assertFalse(w["enabled"])
        self.assertEqual(w["domains"], ["x.example"])

    def test_page_shows_connect_button(self):
        page = self.c.get("/").text
        self.assertIn('id="warp-connect-btn"', page)
        self.assertNotIn("@@WARP", page)


if __name__ == "__main__":
    unittest.main()
