"""
Скользящее окно истории трафика (интерфейс awg0 + каскад), в памяти процесса.

Раз в HISTORY_INTERVAL секунд фоновый поток снимает:
  - суммарные transfer_rx/tx по всем пирам awg0 (через `awg show dump`,
    тот же источник, что и живой статус пиров) — это "сколько трафика
    прошло через сервер вообще",
  - uplink/downlink каскадного xray-процесса (cascade.traffic_stats()) —
    это отдельная, более узкая метрика: "реально ли каскад что-то гоняет
    через VLESS прямо сейчас", а не просто "включен в настройках".

Подробное окно (раз в 5 секунд) живёт в памяти — это дашборд "что
происходит прямо сейчас". Поминутный слепок дополнительно откладывается в
БД и подтягивается обратно при старте, поэтому перезапуск контейнера
больше не обнуляет графики. Хранится 30 дней, дальше подрезается.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone

from datetime import timedelta

from . import awg_manager, cascade, wg_status
from .database import SessionLocal
from .models import ServerConfig, TrafficSample

HISTORY_INTERVAL = 5  # секунд между замерами
HISTORY_MAX = 1080  # 1080 * 5s = 1.5 часа в памяти

# В БД откладываем поминутно: 5-секундная подробность нужна живому графику,
# а на длинной дистанции она превращается в сотни тысяч строк ни за чем.
PERSIST_EVERY_SECONDS = 60
RETENTION_DAYS = 30
PRUNE_EVERY_SECONDS = 3600

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


def _persist(point: dict) -> None:
    db = SessionLocal()
    try:
        db.add(TrafficSample(
            at=datetime.fromisoformat(point["t"]),
            iface_rx=point["iface_rx"],
            iface_tx=point["iface_tx"],
            cascade_uplink=point["cascade_uplink"],
            cascade_downlink=point["cascade_downlink"],
        ))
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


def _prune() -> None:
    db = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=RETENTION_DAYS)
        db.query(TrafficSample).filter(TrafficSample.at < cutoff).delete()
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


def _restore_from_db() -> None:
    """Подтягиваем сохранённую историю в память при старте, чтобы график не
    начинался с чистого листа после каждого перезапуска контейнера."""
    db = SessionLocal()
    try:
        rows = (db.query(TrafficSample)
                  .order_by(TrafficSample.at.desc())
                  .limit(HISTORY_MAX)
                  .all())
    except Exception:
        return
    finally:
        db.close()
    with _lock:
        _history.extend({
            "t": row.at.isoformat(),
            "iface_rx": row.iface_rx,
            "iface_tx": row.iface_tx,
            "cascade_enabled": True,
            "cascade_running": True,
            "cascade_uplink": row.cascade_uplink,
            "cascade_downlink": row.cascade_downlink,
        } for row in reversed(rows))


def run(stop_event: threading.Event) -> None:
    _restore_from_db()
    last_persist = 0.0
    last_prune = 0.0
    while not stop_event.is_set():
        try:
            _sample_once()
            now = time.monotonic()
            if now - last_persist >= PERSIST_EVERY_SECONDS:
                with _lock:
                    latest = _history[-1] if _history else None
                if latest:
                    _persist(latest)
                last_persist = now
            if now - last_prune >= PRUNE_EVERY_SECONDS:
                _prune()
                last_prune = now
        except Exception:
            # Сбор метрик не имеет права ронять панель.
            pass
        stop_event.wait(HISTORY_INTERVAL)
