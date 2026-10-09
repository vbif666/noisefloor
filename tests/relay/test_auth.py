"""
Вход в панель релея: форма логина + подписанная cookie, без Basic-авторизации.

TestClient без контекстного менеджера - lifespan (запуск xray) не нужен,
проверяется только авторизация. base_url https: cookie сессии с флагом
Secure по http клиент обратно не отправит.
"""
import os
import tempfile
import time
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="relay-test-"))
os.environ.setdefault("ADMIN_PASSWORD", "test")

import app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


def client() -> TestClient:
    return TestClient(app.app, base_url="https://testserver", follow_redirects=False)


class LoginTests(unittest.TestCase):
    def setUp(self):
        app._failed_logins.clear()

    def login(self, c, password=None):
        return c.post("/login", data={"username": app.ADMIN_USER,
                                      "password": password or app.ADMIN_PASSWORD})

    def test_page_redirects_to_login(self):
        r = client().get("/")
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/login")

    def test_api_without_session_is_401_without_basic_challenge(self):
        r = client().get("/api/status")
        self.assertEqual(r.status_code, 401)
        # Без WWW-Authenticate: Basic браузер не покажет своё окно пароля.
        self.assertNotIn("www-authenticate", {k.lower() for k in r.headers})

    def test_basic_auth_is_not_accepted(self):
        r = client().get("/api/status", auth=(app.ADMIN_USER, app.ADMIN_PASSWORD))
        self.assertEqual(r.status_code, 401)

    def test_login_form_is_public(self):
        r = client().get("/login")
        self.assertEqual(r.status_code, 200)
        self.assertIn('name="password"', r.text)

    def test_successful_login_sets_secure_cookie(self):
        c = client()
        r = self.login(c)
        self.assertEqual(r.status_code, 303)
        cookie = r.headers["set-cookie"].lower()
        for flag in ("httponly", "secure", "samesite=strict"):
            self.assertIn(flag, cookie)
        self.assertEqual(c.get("/api/traffic-history").status_code, 200)

    def test_wrong_password(self):
        r = self.login(client(), password="wrong")
        self.assertEqual(r.status_code, 401)
        self.assertIn("Неверный", r.text)

    def test_bruteforce_is_throttled(self):
        c = client()
        for _ in range(app.LOGIN_MAX_ATTEMPTS):
            self.login(c, password="wrong")
        r = self.login(c)  # даже верный пароль - пока блокировка
        self.assertEqual(r.status_code, 429)

    def test_logout_drops_session(self):
        c = client()
        self.login(c)
        r = c.post("/logout")
        self.assertEqual(r.status_code, 303)
        self.assertEqual(c.get("/api/traffic-history").status_code, 401)

    def test_forged_and_expired_sessions_rejected(self):
        self.assertFalse(app.session_valid("garbage"))
        token = app.make_session()
        body, _, sig = token.rpartition(".")
        self.assertFalse(app.session_valid(body + "." + "0" * len(sig)))
        with mock.patch("time.time", return_value=time.time() + app.SESSION_TTL_SECONDS + 1):
            self.assertFalse(app.session_valid(token))
        self.assertTrue(app.session_valid(token))

    def test_health_and_sync_stay_outside_login(self):
        self.assertNotEqual(client().get("/api/health").status_code, 303)
        r = client().get("/api/sync")
        self.assertEqual(r.status_code, 401)
        self.assertIn("токен", r.json()["detail"])


if __name__ == "__main__":
    unittest.main()
