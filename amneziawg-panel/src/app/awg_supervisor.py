"""
Надзор за интерфейсом туннеля: поднимает awg0, если он пропал.

Авария 2026-09-20: на сервере с 1 ГБ памяти OOM-killer убил userspace-
процесс amneziawg-go. Интерфейс исчез, UDP-порт перестал слушаться, все
клиенты потеряли VPN — а контейнер при этом оставался «healthy», потому что
проверка здоровья спрашивала только веб-панель. Панель жила, туннеля не было,
и никто об этом не узнал, пока не пожаловались люди.

Здесь два ответа на это:
  * фоновый цикл раз в SUPERVISE_INTERVAL_SECONDS смотрит, есть ли интерфейс,
    и если он должен быть, а его нет — применяет текущий конфиг заново
    (awg-quick up), с экспоненциальной паузой между неудачными попытками;
  * health() отдаёт состояние для /api/health и HEALTHCHECK: контейнер
    считается здоровым, только когда туннель, которого от него ждут, поднят.

«Ждут» означает: утилиты доступны и живое управление включено, и при этом
либо интерфейс поднимается автоматически при старте, либо панель уже хоть
раз успешно применяла конфиг. Свежая установка с выключенным авто-применением
ничего не должна — и здоровьем не страдает.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone

from . import awg_manager
from .config import settings

SUPERVISE_INTERVAL_SECONDS = 30
BACKOFF_START_SECONDS = 5
BACKOFF_MAX_SECONDS = 300

_lock = threading.Lock()
_health: dict = {
    "interface": settings.awg_interface,
    "expected_up": None,   # None — ещё не проверяли
    "interface_up": None,
    "checked_at": None,
    "restarts": 0,
    "last_restart_at": None,
    "last_error": None,
}


def expected_up(server) -> bool:
    """Должен ли интерфейс быть поднят прямо сейчас."""
    if not awg_manager.tools_available():
        return False
    if settings.auto_apply_on_start:
        return True
    return getattr(server, "last_apply_status", None) == "ok"


def _record(server, up: bool | None, error: str | None = None) -> None:
    with _lock:
        _health["interface"] = getattr(server, "interface_name", settings.awg_interface)
        _health["expected_up"] = expected_up(server) if server is not None else False
        _health["interface_up"] = up
        _health["checked_at"] = datetime.now(timezone.utc).isoformat()
        if error is not None:
            _health["last_error"] = error


def check(server) -> bool:
    """Одноразовая проверка: True, если всё как ожидается (интерфейс есть, или
    его и не должно быть). Обновляет health()."""
    if server is None or not expected_up(server):
        _record(server, None)
        return True
    up = awg_manager.interface_is_up(server.interface_name)
    _record(server, up, None if up else f"интерфейс {server.interface_name} не поднят")
    return up


def health() -> dict:
    with _lock:
        data = dict(_health)
    # Здоров, пока не доказано обратное: до первой проверки и когда туннеля
    # не ждут, ok=True — иначе HEALTHCHECK ронял бы контейнер на старте.
    data["ok"] = not (data["expected_up"] and data["interface_up"] is False)
    return data


def supervise(stop_event) -> None:
    """Фоновый цикл: пропал интерфейс — поднимаем заново."""
    from . import config_sync
    from .database import SessionLocal
    from .models import ServerConfig

    backoff = BACKOFF_START_SECONDS
    while not stop_event.wait(SUPERVISE_INTERVAL_SECONDS):
        db = SessionLocal()
        try:
            server = db.query(ServerConfig).first()
            if check(server):
                backoff = BACKOFF_START_SECONDS
                continue

            print(f"[awg-supervisor] интерфейс {server.interface_name} пропал — поднимаю заново")
            result = config_sync.apply_current_config(db)
            with _lock:
                _health["restarts"] += 1
                _health["last_restart_at"] = datetime.now(timezone.utc).isoformat()
            if not result.ok or not awg_manager.interface_is_up(server.interface_name):
                _record(server, False, result.output or "awg-quick up не поднял интерфейс")
                print(f"[awg-supervisor] не удалось: {result.output}; повтор через {backoff}с")
                stop_event.wait(backoff)
                backoff = min(backoff * 2, BACKOFF_MAX_SECONDS)
                continue
            _record(server, True)
            print(f"[awg-supervisor] интерфейс {server.interface_name} снова поднят")
            backoff = BACKOFF_START_SECONDS
        except Exception as exc:  # надзор не должен умирать от одной ошибки
            print(f"[awg-supervisor] ошибка: {exc}")
        finally:
            db.close()
