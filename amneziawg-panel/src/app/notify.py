"""
Уведомления о смене состояний: webhook и Telegram-бот.

Шлём только смену, а не состояние: Limiter помнит, что уже сказано, не даёт
мигающему состоянию заспамить канал и ограничивает частоту. Переживает перезапуск
панели через файл состояния: иначе падение, случившееся во время обновления,
прошло бы незамеченным.

api.telegram.org из России напрямую недоступен, поэтому отправка идёт через
каскад, с прямой попыткой на случай, если каскад лежит. Если не сработало ни то,
ни другое, сообщение ждёт в очереди. О падении самой панели сообщает релей.
"""
from __future__ import annotations

import json
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .config import DATA_DIR, settings
from .fsutil import atomic_write

CONFIG_PATH = DATA_DIR / "notify.json"
STATE_PATH = DATA_DIR / "notify-state.json"

QUEUE_LIMIT = 50
CURL_TIMEOUT_SECONDS = 15
# Такой фразой сверка отпечатка в cascade_sync сообщает о несовпадении. Саму
# сверку отсюда не трогаем, только читаем её вердикт в sync_error релея.
PIN_MISMATCH_MARK = "не совпадает с запомненным"

_lock = threading.RLock()
_limiter = None
_queue: list[str] = []
_delivery: dict = {"last_sent_at": None, "last_error": None}


class Limiter:
    """Дедупликация и ограничение частоты. Без сети и файлов.

    observe - состояние с двумя и более значениями: сообщаем о смене. Новое
    значение должно продержаться hold секунд, вернувшееся раньше срока не даёт
    сообщения вовсе. По одному ключу не чаще раза в min_interval секунд, отложенное
    дойдёт позже.
    event - разовое событие, повтор раньше min_interval отбрасывается.
    Всего не больше max_per_hour сообщений в час: отложенное ждёт, разовое
    отбрасывается, и следующее сообщение скажет, сколько пропущено."""

    def __init__(self, min_interval: float, max_per_hour: int, clock=time.time, state: dict | None = None):
        state = state or {}
        self.min_interval = min_interval
        self.max_per_hour = max_per_hour
        self.clock = clock
        self.known: dict = state.get("known", {})
        self.last_at: dict = state.get("last_at", {})
        self.sent_at: list = state.get("sent_at", [])
        self.suppressed: int = state.get("suppressed", 0)
        self.pending: dict = state.get("pending", {})

    def dump(self) -> dict:
        return {"known": self.known, "last_at": self.last_at, "sent_at": self.sent_at,
                "suppressed": self.suppressed, "pending": self.pending}

    def _take_slot(self, now: float) -> bool:
        self.sent_at = [t for t in self.sent_at if now - t < 3600]
        if len(self.sent_at) >= self.max_per_hour:
            return False
        self.sent_at.append(now)
        return True

    def _with_suppressed(self, text: str) -> str:
        if not self.suppressed:
            return text
        text = f"{text} (ещё сообщений пропущено: {self.suppressed})"
        self.suppressed = 0
        return text

    def observe(self, key: str, value, text: str, *, quiet_first: bool = True, hold: float = 0) -> None:
        if key not in self.known and quiet_first:
            self.known[key] = value
            return
        if key in self.known and self.known[key] == value:
            self.pending.pop(key, None)
            return
        waiting = self.pending.get(key)
        since = waiting["since"] if waiting and waiting["value"] == value else self.clock()
        self.pending[key] = {"value": value, "text": text, "since": since, "hold": hold}

    def event(self, key: str, text: str) -> str | None:
        now = self.clock()
        if now - self.last_at.get(key, 0) < self.min_interval or not self._take_slot(now):
            self.suppressed += 1
            return None
        self.last_at[key] = now
        return self._with_suppressed(text)

    def due(self) -> list[str]:
        """Что пора отправить из отложенного."""
        now = self.clock()
        out = []
        for key, item in list(self.pending.items()):
            if now - item["since"] < item["hold"] or now - self.last_at.get(key, 0) < self.min_interval:
                continue
            if not self._take_slot(now):
                break
            self.known[key] = item["value"]
            self.last_at[key] = now
            del self.pending[key]
            out.append(self._with_suppressed(item["text"]))
        return out


# ------------------------------------------------------------- настройки ---

def load_config() -> dict:
    config = {"webhook_url": "", "telegram_token": settings.notify_telegram_token,
              "telegram_chat_id": settings.notify_telegram_chat_id}
    try:
        saved = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        saved = {}
    if isinstance(saved, dict):
        # Сохранённое важнее .env, и пустое тоже: иначе бота не выключить из интерфейса.
        config.update({k: str(saved[k] or "") for k in config if k in saved})
    return config


def save_config(config: dict) -> None:
    atomic_write(CONFIG_PATH, json.dumps(config, ensure_ascii=False), mode=0o600)


def configured(config: dict) -> bool:
    return bool(config["webhook_url"] or (config["telegram_token"] and config["telegram_chat_id"]))


def valid_url(url: str) -> bool:
    parts = urlsplit(url)
    return parts.scheme in ("http", "https") and bool(parts.hostname)


def public_settings() -> dict:
    """Для интерфейса: токен бота наружу не отдаём."""
    config = load_config()
    with _lock:
        delivery = dict(_delivery)
        queued = len(_queue)
    return {"webhook_url": config["webhook_url"], "telegram_chat_id": config["telegram_chat_id"],
            "telegram_token_set": bool(config["telegram_token"]), "queued": queued, **delivery}


# --------------------------------------------------------------- отправка ---

def _curl_quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _post(url: str, payload: dict, proxy: str | None) -> str | None:
    """POST с JSON. None - доставлено, иначе текст ошибки. Адрес и тело идут через
    stdin: токен бота в адресе не должен попадать в список процессов."""
    body = json.dumps(payload)
    lines = [f"url = {_curl_quote(url)}", 'header = "Content-Type: application/json"',
             f"data-binary = {_curl_quote(body)}"]
    if proxy:
        lines.append(f"proxy = {_curl_quote(proxy)}")
    try:
        result = subprocess.run(
            ["curl", "--silent", "--output", "/dev/null", "--write-out", "%{http_code}",
             "--max-time", str(CURL_TIMEOUT_SECONDS), "--config", "-"],
            input="\n".join(lines), capture_output=True, text=True, timeout=CURL_TIMEOUT_SECONDS + 5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"curl не выполнился: {exc}"
    code = (result.stdout or "").strip()
    if code.startswith("2"):
        return None
    return f"сервер ответил {code}" if code not in ("", "000") else "соединение не установлено"


def _routes() -> list[str | None]:
    from . import cascade
    return [f"socks5h://127.0.0.1:{cascade.PROBE_PORT}", None] if cascade.is_running() else [None]


def _send_route(url: str, payload: dict) -> str | None:
    error = None
    for proxy in _routes():
        error = _post(url, payload, proxy)
        if error is None:
            return None
    return error


def send(config: dict, text: str) -> str | None:
    """None, если дошло хотя бы по одному каналу."""
    errors = []
    delivered = False
    if config["webhook_url"]:
        error = _send_route(config["webhook_url"], {"text": text})
        delivered = delivered or error is None
        errors += [f"webhook: {error}"] if error else []
    if config["telegram_token"] and config["telegram_chat_id"]:
        url = f"{settings.notify_telegram_api.rstrip('/')}/bot{config['telegram_token']}/sendMessage"
        error = _send_route(url, {"chat_id": config["telegram_chat_id"], "text": text})
        delivered = delivered or error is None
        errors += [f"telegram: {error}"] if error else []
    if not errors and not delivered:
        return "не настроено ни одного канала"
    with _lock:
        _delivery["last_error"] = "; ".join(errors) or None
        if delivered:
            _delivery["last_sent_at"] = datetime.now(timezone.utc).isoformat()
    return None if delivered else "; ".join(errors)


def send_test() -> str | None:
    return send(load_config(), _format("тестовое сообщение"))


def _format(text: str) -> str:
    when = datetime.now(timezone.utc).strftime("%H:%M UTC")
    return f"NOISEFLOOR {socket.gethostname()}, {when}: {text}"


# ---------------------------------------------------------------- очередь ---

def limiter() -> Limiter:
    global _limiter
    with _lock:
        if _limiter is None:
            try:
                state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                state = {}
            state = state if isinstance(state, dict) else {}
            _queue[:] = [str(t) for t in state.get("queue", [])][-QUEUE_LIMIT:]
            _limiter = Limiter(settings.notify_min_interval_seconds, settings.notify_max_per_hour, state=state)
        return _limiter


def _enqueue(texts: list[str]) -> None:
    """Пока каналов нет, сообщения не копятся: иначе включение выдало бы старьё."""
    if texts and configured(load_config()):
        _queue.extend(_format(text) for text in texts)
        del _queue[:-QUEUE_LIMIT]


def _save() -> None:
    try:
        atomic_write(STATE_PATH, json.dumps({**limiter().dump(), "queue": _queue}, ensure_ascii=False))
    except OSError as exc:
        print(f"[notify] состояние не сохранено: {exc}")


def event(key: str, text: str) -> None:
    """Разовое событие. Зовётся из надзора, поэтому не бросает исключений и
    ничего не отправляет сама."""
    try:
        with _lock:
            sent = limiter().event(key, text)
            if sent:
                _enqueue([sent])
            _save()
    except Exception as exc:
        print(f"[notify] {exc}")


def deliver() -> None:
    """Отправить очередь. На первой неудаче стоп, порядок сообщений важен."""
    config = load_config()
    while True:
        with _lock:
            if not _queue:
                return
            text = _queue[0]
        if send(config, text) is not None:
            return
        with _lock:
            if _queue and _queue[0] == text:
                _queue.pop(0)
            _save()


# ---------------------------------------------------------------- состояния ---

def _observe_update(lim: Limiter) -> None:
    from . import self_update
    try:
        result = json.loads(self_update.RESULT_FILE.read_text(encoding="utf-8"))
        finished = result["finished_at"]
    except (OSError, ValueError, KeyError, TypeError):
        return
    if result.get("rolled_back"):
        text = f"обновление откатилось: {result.get('message')}"
    elif not result.get("ok"):
        text = f"обновление не удалось: {result.get('message')}"
    elif result.get("from") == result.get("to"):
        return
    else:
        text = f"обновление установлено: {result.get('from')} -> {result.get('to')}"
    lim.observe("update", finished, text)


def _observe_relays(lim: Limiter, db_relays: list) -> None:
    from . import cascade
    hold = settings.notify_hold_seconds
    if cascade.running_relay_count() >= 2 and cascade.is_running():
        active = cascade.active_relay()
        lim.observe("relay", active or "none",
                    f"каскад переключился на релей {active}" if active else "все релеи недоступны",
                    quiet_first=bool(active), hold=hold)
    for relay in db_relays:
        mismatch = PIN_MISMATCH_MARK in (relay.sync_error or "")
        lim.observe(f"pin:{relay.id}", mismatch,
                    f"отпечаток релея {relay.sync_url} не совпал, синхронизация остановлена"
                    if mismatch else f"отпечаток релея {relay.sync_url} снова совпадает",
                    quiet_first=not mismatch)


def _observe_canary(lim: Limiter) -> None:
    from . import canary
    state = canary.status()
    if state["ok"] is None:
        return
    lim.observe("canary", state["ok"],
                "канарейка восстановилась, каскад работает" if state["ok"]
                else f"канарейка упала: {state['stage']}: {state['error']}",
                quiet_first=state["ok"], hold=settings.notify_hold_seconds)


def _observe_backup(lim: Limiter) -> None:
    from . import backup
    state = backup.status()
    if state["last_error"]:
        lim.observe("backup", False, f"бэкап не удался: {state['last_error']}", quiet_first=False)
    elif state["last_success_at"]:
        lim.observe("backup", True, "бэкап снова создаётся")


def collect(db) -> None:
    """Сверить состояния. Источники независимы: сбой одного не мешает остальным."""
    from .models import CascadeRelay

    lim = limiter()
    for source in (
        lambda: _observe_canary(lim),
        lambda: _observe_relays(lim, list(db.query(CascadeRelay).all())),
        lambda: _observe_update(lim),
        lambda: _observe_backup(lim),
    ):
        try:
            with _lock:
                source()
        except Exception as exc:
            print(f"[notify] {exc}")


def step(db) -> None:
    collect(db)
    with _lock:
        _enqueue(limiter().due())
        _save()
    deliver()


def run(stop_event: threading.Event) -> None:
    from .database import SessionLocal

    while not stop_event.wait(settings.notify_interval_seconds):
        db = SessionLocal()
        try:
            step(db)
        except Exception as exc:
            print(f"[notify] {exc}")
        finally:
            db.close()
