"""
Обновление самой панели: как она решает, что вышла новая версия, и как
просит хост её поставить.

Сеть здесь подменяется целиком: тесты не ходят ни в GitHub, ни в Docker Hub.
"""
import json
import pathlib
import tempfile
import unittest
from unittest import mock

from app import self_update
from app.self_update import Available, Build


def _release(tag="v1.2.0", published="2026-09-13T10:00:00Z", body="что нового"):
    return {"tag_name": tag, "published_at": published, "body": body,
            "html_url": f"https://github.com/vbif666/noisefloor/releases/tag/{tag}"}


class ReleaseComparisonTests(unittest.TestCase):
    def test_dev_build_always_sees_release(self):
        # Сборке без штампа сравнивать не с чем — пусть оператор знает о релизе.
        self.assertTrue(self_update._release_is_newer(
            Build("dev", "unknown", "unknown"), Available("v1.0.0", None, "2026-09-13T00:00:00Z", "", "")))

    def test_same_release_is_not_an_update(self):
        self.assertFalse(self_update._release_is_newer(
            Build("v1.2.0", "abc1234", "2026-09-13T09:00:00Z"), Available("v1.2.0", None, "2026-09-13T10:00:00Z", "", "")))

    def test_other_release_is_an_update(self):
        self.assertTrue(self_update._release_is_newer(
            Build("v1.1.0", "abc1234", "2026-09-01T00:00:00Z"), Available("v1.2.0", None, "2026-09-13T10:00:00Z", "", "")))

    def test_between_releases_compares_dates(self):
        # Сборка между релизами (git describe): релиз новее её — обновление;
        # старше — нет, даже если номер другой.
        between = Build("v1.1.0-3-gabc1234", "abc1234", "2026-09-10T00:00:00Z")
        self.assertTrue(self_update._release_is_newer(between, Available("v1.2.0", None, "2026-09-13T10:00:00Z", "", "")))
        self.assertFalse(self_update._release_is_newer(between, Available("v1.1.0", None, "2026-09-01T00:00:00Z", "", "")))


class LatestChannelTests(unittest.TestCase):
    """Канал latest: реестр не знает коммитов, но CI кладёт рядом с latest
    тег sha-XXXX с тем же digest."""

    def _tags(self, latest_digest="sha256:aaa", sha_tag="sha-685321b"):
        return {"results": [
            {"name": "latest", "digest": latest_digest, "last_updated": "2026-09-13T10:00:00Z"},
            {"name": sha_tag, "digest": latest_digest},
            {"name": "sha-f4b95f3", "digest": "sha256:bbb"},
        ]}

    def test_finds_commit_behind_latest_by_digest(self):
        with mock.patch.object(self_update, "_get_json", return_value=self._tags()):
            digest, sha, _ = self_update._latest_commit_image()
        self.assertEqual(sha, "685321b")

    def test_same_commit_is_not_an_update(self):
        with mock.patch.object(self_update, "_get_json", return_value=self._tags()):
            _, newer = self_update._latest_master(Build("v1-g685321b", "685321b", "x"))
        self.assertFalse(newer)

    def test_prefix_match_tolerates_hash_length(self):
        # Короткие хеши бывают 7 и 12 символов — это один коммит.
        with mock.patch.object(self_update, "_get_json", return_value=self._tags(sha_tag="sha-685321b0abcd")):
            _, newer = self_update._latest_master(Build("x", "685321b", "x"))
        self.assertFalse(newer)

    def test_other_commit_is_an_update(self):
        with mock.patch.object(self_update, "_get_json", side_effect=[self._tags(), {"commits": [
                {"commit": {"message": "Российские адреса — напрямую\n\nподробности"}}]}]):
            latest, newer = self_update._latest_master(Build("x", "f4b95f3", "x"))
        self.assertTrue(newer)
        self.assertEqual(latest.sha, "685321b")
        self.assertIn("Российские адреса", latest.notes)

    def test_hand_built_latest_without_sha_tag_is_not_offered(self):
        tags = {"results": [{"name": "latest", "digest": "sha256:zzz", "last_updated": "x"}]}
        with mock.patch.object(self_update, "_get_json", return_value=tags):
            _, newer = self_update._latest_master(Build("x", "abc", "x"))
        self.assertFalse(newer)


class AgentHandshakeTests(unittest.TestCase):
    """Панель и хостовый агент общаются файлами в каталоге данных."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = pathlib.Path(self.tmp.name)
        self.patches = [
            mock.patch.object(self_update, "REQUEST_FILE", d / "update-request.json"),
            mock.patch.object(self_update, "RESULT_FILE", d / "update-result.json"),
            mock.patch.object(self_update, "AGENT_FILE", d / "agent.json"),
            mock.patch.object(self_update, "_state", None),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        self.dir = d

    def test_without_agent_button_is_refused_with_manual_hint(self):
        ok, message = self_update.request_update()
        self.assertFalse(ok)
        self.assertIn("docker compose pull", message)
        self.assertFalse((self.dir / "update-request.json").exists())

    def test_with_agent_request_is_written(self):
        (self.dir / "agent.json").write_text("{}")
        ok, _ = self_update.request_update()
        self.assertTrue(ok)
        request = json.loads((self.dir / "update-request.json").read_text())
        self.assertIn("requested_at", request)
        self.assertTrue(self_update.status().pending)

    def test_second_request_while_pending_is_idempotent(self):
        (self.dir / "agent.json").write_text("{}")
        self_update.request_update()
        ok, message = self_update.request_update()
        self.assertTrue(ok)
        self.assertIn("уже", message)

    def test_agent_result_is_surfaced(self):
        (self.dir / "update-result.json").write_text(json.dumps({"ok": False, "rolled_back": True, "message": "не поднялась"}))
        state = self_update.status()
        self.assertFalse(state.last_result["ok"])
        self.assertTrue(state.last_result["rolled_back"])


class NoReleasesYetTests(unittest.TestCase):
    def test_404_means_no_releases_not_an_error(self):
        import urllib.error
        err = urllib.error.HTTPError("u", 404, "Not Found", {}, None)
        with mock.patch.object(self_update, "_state", None), \
                mock.patch.object(self_update, "_get_json", side_effect=err):
            state = self_update.check()
        self.assertIsNone(state.check_error)
        self.assertIsNone(state.latest)
        self.assertFalse(state.available)


class CheckResilienceTests(unittest.TestCase):
    def test_network_error_keeps_state_and_reports(self):
        import urllib.error
        with mock.patch.object(self_update, "_state", None), \
                mock.patch.object(self_update, "_get_json", side_effect=urllib.error.URLError("нет сети")):
            state = self_update.check()
        self.assertIsNotNone(state.check_error)
        self.assertFalse(state.available)
        self.assertIsNotNone(state.checked_at)


if __name__ == "__main__":
    unittest.main()
