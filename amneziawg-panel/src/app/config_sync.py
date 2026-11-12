from __future__ import annotations

import threading
from datetime import datetime, timezone

from sqlalchemy.orm import Session, object_session

from . import awg_config, awg_manager, cascade, vless_server, wg_status
from .models import Peer, ServerConfig, Tunnel

# Код `noisefloor-rules check`: правила снесли снаружи (ufw reset, iptables -F).
RULES_DRIFT_EXIT_CODE = 4

# Применение конфига целиком, от чтения БД до правил фаервола. Запросы панели
# идут в разных потоках, а ещё есть надзор и синхронизация с релеем. Без замка
# поток с более старым снимком пиров мог записать конфиг последним и убрать с
# интерфейса только что созданного клиента. RLock: под ним же выделяется адрес
# клиента, а применение зовётся и изнутри.
apply_lock = threading.RLock()

_rules_lock = threading.Lock()
_rules_status: dict = {
    "ok": None,            # None: ещё не проверяли или правил быть не должно
    "error": None,
    "restored": 0,         # сколько раз вернули снесённые снаружи правила
    "last_restored_at": None,
}


def rules_status() -> dict:
    with _rules_lock:
        return dict(_rules_status)


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


def ensure_rules(server: ServerConfig, interfaces: list[str]) -> awg_manager.CommandResult | None:
    """Привести правила к нужному виду, сверяясь с ядром, а не с памятью.

    Запомненные аргументы последнего запуска ничего не говорили о том, что
    стоит на самом деле: снесённые снаружи правила считались применёнными, и
    вернуть их мог только перезапуск туннеля. PostUp тут не помогает: при
    горячем применении (syncconf) он не срабатывает, а его сбой намеренно не
    снимает интерфейс.

    None: правил здесь быть не должно или управлять ими нечем."""
    if not server.egress_interface or not awg_manager.tools_available():
        return None
    up, _down = awg_config.rules_commands(server, interfaces)
    with apply_lock:
        state = awg_manager.run_rules([up[0], "check", *up[2:]])
        if state.ok:
            with _rules_lock:
                _rules_status.update(ok=True, error=None)
            return state

        drifted = state.code == RULES_DRIFT_EXIT_CODE
        result = awg_manager.run_rules(up)
    with _rules_lock:
        _rules_status.update(ok=result.ok, error=None if result.ok else result.output)
        if result.ok and drifted:
            _rules_status["restored"] += 1
            _rules_status["last_restored_at"] = datetime.now(timezone.utc).isoformat()
    if not result.ok:
        print(f"[rules] не удалось поставить правила: {result.output}")
    elif drifted:
        print(f"[rules] правила восстановлены: {state.output}")
        from . import notify
        notify.event("rules_restored", f"правила фаервола снесли снаружи, надзор вернул их: {state.output}")
    return result


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
    # параметры — иначе применим заведомо устаревшую ссылку. Это сетевой
    # запрос, поэтому до замка: недоступный релей не должен держать всю панель.
    if server.cascade_enabled:
        from . import cascade_sync
        cascade_sync.sync_once(db)

    with apply_lock:
        # Сохранить то, что вызывающий ещё не закоммитил, и сбросить кэш сессии:
        # читать надо то, что есть в БД к моменту получения замка.
        db.commit()
        return _apply_locked(db, restart=restart, restart_tunnels=restart_tunnels)


def _apply_locked(db: Session, *, restart: bool,
                  restart_tunnels: frozenset[str]) -> awg_manager.CommandResult:
    server = get_server(db)

    # Каскад (xray -> VLESS) применяется ДО рендера awg-конфига: REDIRECT-
    # правило в PostUp имеет смысл только если процесс, на который оно
    # заворачивает трафик, реально поднят.
    # Вход VLESS переезжает между отдельным xray и xray каскада, порт один:
    # сначала отпустить его, потом занимать (см. vless_server).
    if vless_server.cascade_wanted(server):
        vless_server.stop()
    server.cascade_last_error = cascade.sync(server)
    vless_server.sync(server)

    peers = db.query(Peer).all()
    interfaces = interface_names(db, server)
    config_text = awg_config.full_server_config(server, peers, interfaces[1:])

    if restart:
        result = awg_manager.restart(server.interface_name, config_text)
    else:
        result = awg_manager.apply(server.interface_name, config_text)

    _apply_tunnels(db, server, peers, restart_tunnels=restart_tunnels)
    rules = ensure_rules(server, interfaces)
    if result.ok and rules is not None and not rules.ok:
        # Интерфейс поднят, но без правил у клиентов нет ни NAT, ни каскада:
        # для админа это неудачное применение, а не успех.
        result = awg_manager.CommandResult(False, f"правила фаервола не применены: {rules.output}")

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
