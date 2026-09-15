"""
Обновление релея через хостовый агент: та же схема файлов, что у панели.
Сеть не трогается.
"""
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="relay-test-"))
os.environ.setdefault("ADMIN_PASSWORD", "test")

import self_update  # noqa: E402
from self_update import Available, Build  # noqa: E402


class ChannelAndBuildTests(unittest.TestCase):
    def test_channel_comes_from_environment_and_defaults_to_stable(self):
        with mock.patch.dict(os.environ, {"UPDATE_CHANNEL": "latest"}):
            self.assertEqual(self_update._channel(), "latest")
        with mock.patch.dict(os.environ, {"UPDATE_CHANNEL": "nonsense"}):
            self.assertEqual(self_update._channel(), "stable")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("UPDATE_CHANNEL", None)
            self.assertEqual(self_update._channel(), "stable")

    def test_image_is_the_relay_one(self):
        self.assertEqual(self_update.IMAGE, "vbif666/noisefloor-vless-reality")

    def test_release_comparison(self):
        self.assertTrue(self_update._release_is_newer(
            Build("v1.0.1", "abc", "2026-09-14T00:00:00Z"), Available("v1.0.2", None, "2026-09-15T00:00:00Z", "", "")))
        self.assertFalse(self_update._release_is_newer(
            Build("v1.0.2", "abc", "2026-09-15T00:00:00Z"), Available("v1.0.2", None, "2026-09-15T00:00:00Z", "", "")))


class AgentHandshakeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = pathlib.Path(self.tmp.name)
        for name, value in (("REQUEST_FILE", d / "update-request.json"), ("RESULT_FILE", d / "update-result.json"),
                            ("AGENT_FILE", d / "agent.json"), ("_state", None)):
            p = mock.patch.object(self_update, name, value); p.start(); self.addCleanup(p.stop)
        self.dir = d

    def test_without_agent_request_is_refused_with_manual_hint(self):
        ok, message = self_update.request_update()
        self.assertFalse(ok)
        self.assertIn("docker compose pull", message)
        self.assertFalse((self.dir / "update-request.json").exists())

    def test_with_agent_request_is_written_and_mentions_cascade(self):
        (self.dir / "agent.json").write_text("{}")
        ok, message = self_update.request_update()
        self.assertTrue(ok)
        self.assertIn("каскад", message)
        request = json.loads((self.dir / "update-request.json").read_text())
        self.assertEqual(request["channel"], "stable")
        self.assertTrue(self_update.status().pending)

    def test_agent_result_is_surfaced(self):
        (self.dir / "update-result.json").write_text(json.dumps({"ok": True, "message": "обновлено до v1.0.3"}))
        self.assertEqual(self_update.status().last_result["message"], "обновлено до v1.0.3")


if __name__ == "__main__":
    unittest.main()
