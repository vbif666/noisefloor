"""
Канарейка: панельная сторона.

cascade.verify() ходит через loopback и минует awg0, iptables, TPROXY и MTU.
Канарейка - отдельный контейнер со своим сетевым пространством, настоящий
AWG-клиент: панель заводит для него служебного пира и кладёт настройки в общий
каталог, а контейнер пишет туда результат проб (см. canary_probe.py).

Каталог общий только с контейнером канарейки. Сначала контейнер заявляет о себе
файлом результата, и только после этого панель заводит пира: на установке без
контейнера ничего не меняется.
"""
import json
import socket
import time
from datetime import datetime, timezone

from . import cascade, config_sync, crypto
from .config import DATA_DIR, settings
from .fsutil import atomic_write
from .ip_pool import next_available_ip
from .models import Peer, ServerConfig

CANARY_DIR = DATA_DIR / "canary"
CONFIG_PATH = CANARY_DIR / "config.json"
RESULT_PATH = CANARY_DIR / "result.json"

SERVICE_PEER_NAME = "canary"
SYNC_INTERVAL_SECONDS = 30
# Проба идёт раз в минуту, дольше трёх минут тишины значит, что контейнер мёртв.
STALE_AFTER_SECONDS = 180


def read_result() -> dict | None:
    try:
        data = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _age(result: dict) -> float:
    try:
        return time.time() - float(result.get("ts", 0))
    except (TypeError, ValueError):
        return float("inf")


def sidecar_present() -> bool:
    result = read_result()
    return result is not None and _age(result) < STALE_AFTER_SECONDS


def status() -> dict:
    """Состояние для API и метрик. ok=None - канарейка не настроена или ждёт."""
    empty = {"ok": None, "checked_at": None, "error": None, "stage": None,
             "exit_ip": None, "duration_ms": None, "speed_bps": None}
    result = read_result()
    if result is None or not CONFIG_PATH.exists():
        return empty
    checked_at = None
    try:
        checked_at = datetime.fromtimestamp(float(result["ts"]), tz=timezone.utc)
    except (KeyError, TypeError, ValueError):
        pass
    if _age(result) >= STALE_AFTER_SECONDS:
        return {**empty, "ok": False, "checked_at": checked_at, "stage": "stale",
                "error": "контейнер канарейки не присылает результатов"}
    if result.get("state") != "probed":
        return empty
    return {
        "ok": bool(result.get("ok")),
        "checked_at": checked_at,
        "error": result.get("error"),
        "stage": result.get("stage"),
        "exit_ip": result.get("exit_ip"),
        "duration_ms": result.get("duration_ms"),
        "speed_bps": result.get("speed_bps"),
    }


def service_peer(db) -> Peer | None:
    return db.query(Peer).filter(Peer.is_service.is_(True)).first()


def _create_service_peer(db, server: ServerConfig) -> Peer:
    priv, pub = crypto.generate_keypair()
    with config_sync.apply_lock:
        used = {a.split("/")[0] for (a,) in db.query(Peer.address).all()}
        used.add(server.address.split("/")[0])
        used.update(t.address.split("/")[0] for t in config_sync.get_tunnels(db))
        peer = Peer(
            name=SERVICE_PEER_NAME,
            private_key=priv,
            public_key=pub,
            preshared_key=crypto.generate_preshared_key(),
            address=next_available_ip(server.address, used),
            allowed_ips_client="0.0.0.0/0",
            persistent_keepalive=25,
            enabled=True,
            note="служебный пир канарейки",
            is_service=True,
        )
        db.add(peer)
        db.commit()
    db.refresh(peer)
    return peer


def expected_exit_ips(server: ServerConfig) -> list[str]:
    """С каких адресов должен выходить трафик: адрес релея или явная настройка.

    Пустой список значит, что сверять не с чем, тогда адрес только показываем."""
    override = (settings.canary_expected_exit_ip or "").strip()
    if override:
        return [ip.strip() for ip in override.split(",") if ip.strip()]
    try:
        host = cascade.parse_vless_url(server.cascade_vless_url or "")["host"]
    except (cascade.VlessParseError, KeyError):
        return []
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return []
    return sorted({info[4][0] for info in infos})


def build_config(peer: Peer, server: ServerConfig) -> dict:
    from .awg_config import client_config
    return {
        "conf": client_config(peer, server),
        "address": peer.address,
        "mtu": server.mtu,
        "dns": (server.dns or "").split(",")[0].strip(),
        "listen_port": server.listen_port,
        "expected_exit_ips": expected_exit_ips(server),
    }


def sync(db) -> None:
    """Привести служебного пира и файл настроек к текущему состоянию."""
    server = db.query(ServerConfig).first()
    if server is None:
        return
    wanted = (
        settings.canary_enabled
        and bool(server.cascade_enabled)
        and bool((server.cascade_vless_url or "").strip())
        and sidecar_present()
    )
    if not wanted:
        # Каскад выключен: контейнер снимает свой интерфейс и ждёт.
        try:
            CONFIG_PATH.unlink()
        except FileNotFoundError:
            pass
        return

    peer = service_peer(db)
    if peer is None:
        peer = _create_service_peer(db, server)
        config_sync.apply_current_config(db)

    content = json.dumps(build_config(peer, server), ensure_ascii=False, sort_keys=True)
    try:
        if CONFIG_PATH.read_text(encoding="utf-8") == content:
            return
    except OSError:
        pass
    atomic_write(CONFIG_PATH, content, mode=0o600)


def run(stop_event) -> None:
    from .database import SessionLocal

    while not stop_event.wait(SYNC_INTERVAL_SECONDS):
        db = SessionLocal()
        try:
            sync(db)
        except Exception as exc:
            print(f"[canary] {exc}")
        finally:
            db.close()
