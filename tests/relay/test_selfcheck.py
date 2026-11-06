"""
Самопроверка релея: когда /api/health считает релей больным и когда нет.
Настоящий xray здесь не запускается, живой проход проверяет tests/smoke.sh.
"""
import os
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="relay-test-"))
os.environ.setdefault("ADMIN_PASSWORD", "test")

import app  # noqa: E402
import selfcheck  # noqa: E402

CREDS = {"vless_port": 8443, "uuid": "u", "sni": "dl.google.com", "public_key": "pub", "short_id": "ab"}


class SelfcheckTests(unittest.TestCase):
    def setUp(self):
        selfcheck.reset()
        self.addCleanup(selfcheck.reset)

    def _run(self, ok=True, direct=204):
        side_effect = None if ok else selfcheck.Failure("нет прохода")
        with mock.patch.object(selfcheck, "through_reality", side_effect=side_effect), \
                mock.patch.object(selfcheck, "_http_code", return_value=direct):
            return selfcheck.run_once(lambda: CREDS, "xray")

    def test_no_result_yet_is_not_healthy(self):
        self.assertFalse(selfcheck.healthy())

    def test_success_is_healthy(self):
        self._run()
        self.assertTrue(selfcheck.healthy())
        self.assertEqual(selfcheck.snapshot()["state"], "ok")

    def test_single_failure_is_forgiven_and_retried_soon(self):
        self._run()
        data = self._run(ok=False)
        self.assertTrue(selfcheck.healthy())
        self.assertEqual(selfcheck.next_delay(data), selfcheck.RETRY_SECONDS)

    def test_two_failures_are_a_breakage(self):
        self._run()
        self._run(ok=False)
        data = self._run(ok=False)
        self.assertFalse(selfcheck.healthy())
        self.assertEqual(data["state"], "failed")
        self.assertEqual(selfcheck.next_delay(data), selfcheck.INTERVAL_SECONDS)

    def test_broken_from_the_start_never_becomes_healthy(self):
        for _ in range(3):
            self._run(ok=False)
            self.assertFalse(selfcheck.healthy())

    def test_recovery(self):
        self._run(ok=False)
        self._run(ok=False)
        self._run()
        self.assertTrue(selfcheck.healthy())
        self.assertEqual(selfcheck.snapshot()["failures"], 0)

    def test_no_internet_at_all_proves_nothing(self):
        data = self._run(ok=False, direct=0)
        self.assertEqual(data["state"], "unknown")
        self.assertTrue(selfcheck.healthy())

    def test_missing_creds_is_a_failure_not_a_crash(self):
        with mock.patch.object(selfcheck, "_http_code", return_value=204):
            selfcheck.run_once(lambda: {}, "xray")
            data = selfcheck.run_once(lambda: {}, "xray")
        self.assertEqual(data["state"], "failed")

    def test_disabled(self):
        with mock.patch.object(selfcheck, "INTERVAL_SECONDS", 0):
            self.assertEqual(selfcheck.snapshot()["state"], "off")
            self.assertTrue(selfcheck.healthy())

    def test_client_config_targets_own_inbound(self):
        out = selfcheck.client_config(CREDS, 1080)["outbounds"][0]
        self.assertEqual(out["settings"]["vnext"][0]["address"], "127.0.0.1")
        self.assertEqual(out["settings"]["vnext"][0]["port"], 8443)
        self.assertEqual(out["streamSettings"]["realitySettings"]["publicKey"], "pub")

    def test_temp_config_with_uuid_is_removed(self):
        seen = {}

        class Proc:
            returncode = None
            def __init__(self, cmd, **_):
                seen["path"] = cmd[3]
            def poll(self):
                return None
            def terminate(self):
                pass
            def wait(self, timeout=None):
                return 0

        with mock.patch.object(selfcheck.subprocess, "Popen", Proc), \
                mock.patch.object(selfcheck, "_wait_port"), \
                mock.patch.object(selfcheck, "_http_code", return_value=204):
            selfcheck.through_reality(CREDS, "xray")
        self.assertFalse(os.path.exists(seen["path"]))


class HealthEndpointTests(unittest.TestCase):
    def setUp(self):
        selfcheck.reset()
        self.addCleanup(selfcheck.reset)
        with app.state_lock:
            app.state["xray_running"] = True
        self.addCleanup(app.state.__setitem__, "xray_running", False)

    def _health(self):
        response = app.api_health()
        return response.status_code, response.body.decode()

    def test_pending_is_503(self):
        self.assertEqual(self._health()[0], 503)

    def test_ok_is_200(self):
        with mock.patch.object(selfcheck, "through_reality"):
            selfcheck.run_once(lambda: CREDS, "xray")
        self.assertEqual(self._health()[0], 200)

    def test_public_health_hides_error_text(self):
        with mock.patch.object(selfcheck, "through_reality", side_effect=selfcheck.Failure("секрет")), \
                mock.patch.object(selfcheck, "_http_code", return_value=204):
            selfcheck.run_once(lambda: CREDS, "xray")
            selfcheck.run_once(lambda: CREDS, "xray")
        code, body = self._health()
        self.assertEqual(code, 503)
        self.assertIn('"selfcheck":"failed"', body)
        self.assertNotIn("секрет", body)

    def test_selfcheck_off_keeps_old_behaviour(self):
        with mock.patch.object(selfcheck, "INTERVAL_SECONDS", 0):
            self.assertEqual(self._health()[0], 200)


class AccessLogTests(unittest.TestCase):
    def test_own_probe_is_not_a_client(self):
        self.assertTrue(app.is_own_probe("127.0.0.1"))
        self.assertFalse(app.is_own_probe("203.0.113.7"))


if __name__ == "__main__":
    unittest.main()
