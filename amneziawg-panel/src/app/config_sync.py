from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from . import awg_config, awg_manager, cascade, wg_status
from .models import Peer, ServerConfig


def get_server(db: Session) -> ServerConfig:
    server = db.query(ServerConfig).first()
    if server is None:
        raise RuntimeError("Server config not initialized — bootstrap should have created it on startup")
    return server


def apply_current_config(db: Session, *, restart: bool = False) -> awg_manager.CommandResult:
    """
    Рендерит текущее состояние БД в awg0.conf и применяет его на живой
    интерфейс (если утилиты awg доступны). Всегда сохраняет статус
    применения в ServerConfig, даже если он неудачный — панель должна
    оставаться источником истины независимо от того, удалось ли применить
    конфиг на сервере прямо сейчас.
    """
    server = get_server(db)

    # Если настроена синхронизация, сначала забираем у релея актуальные
    # параметры — иначе применим заведомо устаревшую ссылку.
    if server.cascade_enabled and (server.cascade_sync_url or "").strip():
        from . import cascade_sync
        cascade_sync.sync_once(db)
        server = get_server(db)

    # Каскад (xray -> VLESS) применяется ДО рендера awg-конфига: REDIRECT-
    # правило в PostUp имеет смысл только если процесс, на который оно
    # заворачивает трафик, реально поднят.
    server.cascade_last_error = cascade.sync(server)

    peers = db.query(Peer).all()
    config_text = awg_config.full_server_config(server, peers)

    if restart:
        result = awg_manager.restart(server.interface_name, config_text)
    else:
        result = awg_manager.apply(server.interface_name, config_text)

    server.last_apply_status = "ok" if result.ok else "error"
    server.last_apply_error = None if result.ok else result.output
    server.last_applied_at = datetime.now(timezone.utc)
    db.add(server)
    db.commit()
    return result


def live_status_by_pubkey(server: ServerConfig) -> dict[str, wg_status.PeerStatus] | None:
    """None означает "статус недоступен" (нет утилит / интерфейс не поднят) —
    это отличается от пустого dict (утилиты есть, но пиров пока нет)."""
    if not awg_manager.tools_available():
        return None
    result = awg_manager.show_dump(server.interface_name)
    if not result.ok:
        return None
    parsed = wg_status.parse_dump(result.output)
    if parsed is None:
        return None
    return parsed.peers
