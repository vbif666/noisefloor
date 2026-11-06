"""
Панель молчит: релей сообщает об этом сам.

Панель обычно сама шлёт уведомления, но если она легла или потеряла каскад, то
некому. Релей стоит за границей, поэтому Telegram ему доступен напрямую. Настройки
в окружении, по умолчанию выключено. Считаем только панели, которые выходили на
связь после запуска релея: релей без настроенной синхронизации молчит.
"""
import http.client
import json
import os
import socket
import time
import urllib.request

WEBHOOK_URL = os.environ.get("NOTIFY_WEBHOOK_URL", "").strip()
TELEGRAM_TOKEN = os.environ.get("NOTIFY_TELEGRAM_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.environ.get("NOTIFY_TELEGRAM_CHAT_ID", "").strip()
TELEGRAM_API = os.environ.get("NOTIFY_TELEGRAM_API", "https://api.telegram.org").rstrip("/")
SILENT_MINUTES = float(os.environ.get("NOTIFY_PANEL_SILENT_MINUTES", "15") or 15)
LABEL = os.environ.get("LABEL", "") or socket.gethostname()

REQUEST_TIMEOUT_SECONDS = 15


class PanelWatch:
    """Молчит панель или нет. Сообщает о смене, неотправленное повторит."""

    def __init__(self, silent_seconds: float, clock=time.time):
        self.silent_seconds = silent_seconds
        self.clock = clock
        self.last_seen: float | None = None
        self.alerted = False

    def seen(self) -> None:
        self.last_seen = self.clock()

    def message(self) -> str | None:
        """Что надо сказать сейчас. Состояние меняет sent(): если отправка не
        удалась, тот же текст вернётся на следующем проходе."""
        if self.last_seen is None:
            return None
        silent = self.clock() - self.last_seen >= self.silent_seconds
        if silent and not self.alerted:
            minutes = int((self.clock() - self.last_seen) // 60)
            return f"панель не синхронизировалась {minutes} мин"
        if not silent and self.alerted:
            return "панель снова на связи"
        return None

    def sent(self) -> None:
        self.alerted = not self.alerted


watch = PanelWatch(SILENT_MINUTES * 60)


def enabled() -> bool:
    return bool(WEBHOOK_URL or (TELEGRAM_TOKEN and TELEGRAM_CHAT_ID))


def _post(url: str, payload: dict) -> bool:
    request = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            return 200 <= response.status < 300
    except (OSError, ValueError, http.client.HTTPException) as exc:
        print(f"[notify] отправка не удалась: {type(exc).__name__}")
        return False


def send(text: str) -> bool:
    text = f"NOISEFLOOR релей {LABEL}: {text}"
    delivered = False
    if WEBHOOK_URL:
        delivered = _post(WEBHOOK_URL, {"text": text}) or delivered
    if TELEGRAM_TOKEN and TELEGRAM_CHAT_ID:
        url = f"{TELEGRAM_API}/bot{TELEGRAM_TOKEN}/sendMessage"
        delivered = _post(url, {"chat_id": TELEGRAM_CHAT_ID, "text": text}) or delivered
    return delivered


def run(stop_event) -> None:
    if not enabled():
        return
    while not stop_event.wait(min(30.0, max(1.0, watch.silent_seconds / 2))):
        text = watch.message()
        if text and send(text):
            watch.sent()
