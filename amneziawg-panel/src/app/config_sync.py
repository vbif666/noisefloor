from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session, object_session

from . import awg_config, awg_manager, cascade, wg_status
from .models import Peer, ServerConfig, Tunnel

# Какой командой noisefloor-rules правила стоят сейчас. PostUp основного
# интерфейса срабатывает только при его подъёме, а горячее применение
# (syncconf) его не трогает. Поэтому, когда включили новый протокол или
# переключили каскад, правила надо поставить заново самим — иначе клиенты
# нового интерфейса остаются без NAT и каскада. None — ещё не знаем.
_applied_rules: list[str] | None = None


def get_server(db: Session) -> ServerConfig:
    server = db.query(ServerConfig).first()
    if server is None:
        raise RuntimeError("Server config not initialized — bootstrap should have created it on startup")
    return server


def get_tunnels(db: Session) -> list[Tunnel]:
    return db.query(Tunnel).order_by(Tunnel.id.asc()).all()


def get_tunnel(db: Session, protocol: str) -> Tunnel | None:
    return db.query(Tunnel).filter(Tunnel.protocol == protocol).first()


def interface_names(db: Session, server: ServerConfig) -> list[str]:
    """Все интерфейсы, которые сейчас должны работать: основной и включённые
    дополнительные."""
    return [server.interface_name] + [t.interface_name for t in get_tunnels(db) if t.enabled]


def _apply_tunnels(db: Session, server: ServerConfig, peers: list[Peer], *,
                   restart_tunnels: frozenset[str] = frozenset()) -> None:
    now = datetime.now(timezone.utc)
    for tunnel in get_tunnels(db):
        if not tunnel.enabled:
            if awg_manager.tools_available() and awg_manager.interface_is_up(tunnel.interface_name):
                awg_manager.down(tunnel.interface_name)
            continue
        text = awg_config.tunnel_config(tunnel, server, peers)
        apply = awg_manager.restart if tunnel.protocol in restart_tunnels else awg_manager.apply
        result = apply(tunnel.interface_name, text)
        tunnel.last_apply_status = "ok" if result.ok else "error"
        tunnel.last_apply_error = None if result.ok else result.output
        tunnel.last_applied_at = now
        db.add(tunnel)


def _ensure_rules(server: ServerConfig, interfaces: list[str], main_was_up: bool, restart: bool,
                  main_ok: bool) -> None:
    global _applied_rules
    if not server.egress_interface:
        return
    up, _down = awg_config.rules_commands(server, interfaces)
    if main_ok and (restart or not main_was_up):
        _applied_rules = up  # PostUp только что отработал с этими аргументами
        return
    if up == _applied_rules or not awg_manager.tools_available():
        return
    result = awg_manager.run_rules(up)
    if result.ok:
        _applied_rules = up
    else:
        print(f"[rules] не удалось переставить правила: {result.output}")


def apply_current_config(db: Session, *, restart: bool = False,
                         restart_tunnels: frozenset[str] = frozenset()) -> awg_manager.CommandResult:
    """
    Рендерит текущее состояние БД в awg0.conf и применяет его на живой
    интерфейс (если утилиты awg доступны). Всегда сохраняет статус
    применения в ServerConfig, даже если он неудачный — панель должна
    оставаться источником истины независимо от того, удалось ли применить
    конфиг на сервере прямо сейчас.

    restart относится только к основному интерфейсу. restart_tunnels —
    протоколы дополнительных интерфейсов, которые нужно перезапустить, а не
    применить горячим способом: смена адреса или профиля обфускации через
    syncconf не доезжает. Остальные дополнительные при этом не трогаются.
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
    interfaces = interface_names(db, server)
    config_text = awg_config.full_server_config(server, peers, interfaces[1:])

    main_was_up = awg_manager.tools_available() and awg_manager.interface_is_up(server.interface_name)
    if restart:
        result = awg_manager.restart(server.interface_name, config_text)
    else:
        result = awg_manager.apply(server.interface_name, config_text)

    _apply_tunnels(db, server, peers, restart_tunnels=restart_tunnels)
    _ensure_rules(server, interfaces, main_was_up, restart, result.ok)

    server.last_apply_status = "ok" if result.ok else "error"
    server.last_apply_error = None if result.ok else result.output
    server.last_applied_at = datetime.now(timezone.utc)
    db.add(server)
    db.commit()
    return result


def live_status_by_pubkey(server: ServerConfig) -> dict[str, wg_status.PeerStatus] | None:
    """None означает "статус недоступен" (нет утилит / интерфейс не поднят) —
    это отличается от пустого dict (утилиты есть, но пиров пока нет).

    Клиенты всех протоколов в одном словаре: публичные ключи уникальны, а
    вызывающему всё равно, через какой интерфейс подключён клиент."""
    if not awg_manager.tools_available():
        return None
    db = object_session(server)
    names = interface_names(db, server) if db is not None else [server.interface_name]
    merged: dict[str, wg_status.PeerStatus] | None = None
    for name in names:
        result = awg_manager.show_dump(name)
        if not result.ok:
            continue
        parsed = wg_status.parse_dump(result.output)
        if parsed is None:
            continue
        merged = {**(merged or {}), **parsed.peers}
    return merged
