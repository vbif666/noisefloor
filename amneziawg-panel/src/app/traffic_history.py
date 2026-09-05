"""
Скользящее окно истории трафика (интерфейс awg0 + каскад), в памяти процесса.

Раз в HISTORY_INTERVAL секунд фоновый поток снимает:
  - суммарные transfer_rx/tx по всем пирам awg0 (через `awg show dump`,
    тот же источник, что и живой статус пиров) — это "сколько трафика
    прошло через сервер вообще",
  - uplink/downlink каскадного xray-процесса (cascade.traffic_stats()) —
    это отдельная, более узкая метрика: "реально ли каскад что-то гоняет
    через VLESS прямо сейчас", а не просто "включен в настройках".

Хранится только в памяти (не переживает перезапуск контейнера) — это
дашборд для "что происходит сейчас", а не журнал для отчётности.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone

from . import awg_manager, cascade, wg_status
from .database import SessionLocal
from .models import ServerConfig

HISTORY_INTERVAL = 5  # секунд между замерами
HISTORY_MAX = 1080  # 1080 * 5s = 1.5 часа в памяти

_history: list[dict] = []
_lock = threading.Lock()


def _sample_once() -> None:
    db = SessionLocal()
    try:
        server = db.query(ServerConfig).first()
        if server is None:
            return

        iface_rx = iface_tx = 0
        if awg_manager.tools_available():
            result = awg_manager.show_dump(server.interface_name)
            if result.ok:
                parsed = wg_status.parse_dump(result.output)
                if parsed:
                    for peer in parsed.peers.values():
                        iface_rx += peer.transfer_rx
                        iface_tx += peer.transfer_tx

        cascade_stats = cascade.traffic_stats() or {}

        point = {
            "t": datetime.now(timezone.utc).isoformat(),
            "iface_rx": iface_rx,
            "iface_tx": iface_tx,
            "cascade_enabled": bool(server.cascade_enabled),
            "cascade_running": cascade.is_running(),
            "cascade_uplink": cascade_stats.get("uplink", 0),
            "cascade_downlink": cascade_stats.get("downlink", 0),
        }
        with _lock:
            _history.append(point)
            if len(_history) > HISTORY_MAX:
                del _history[: len(_history) - HISTORY_MAX]
    finally:
        db.close()


def get_history() -> list[dict]:
    with _lock:
        return list(_history)


def run(stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        try:
            _sample_once()
        except Exception:
            pass
        stop_event.wait(HISTORY_INTERVAL)
