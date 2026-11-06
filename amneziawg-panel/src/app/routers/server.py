import platform

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import canary, cascade, cascade_sync, config_sync, relays
from ..config import settings
from ..database import get_db
from ..obfuscation import random_obfuscation_profile
from ..models import CascadeRelay
from ..schemas import ApplyResult, CascadeStatus, RelayCreate, RelayStatus, ServerRead, ServerUpdate
from ..security import get_current_admin

router = APIRouter()


@router.get("", response_model=ServerRead)
def read_server(db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    return config_sync.get_server(db)


# Поля, смена которых требует перезапуска awg0 (см. update_server). Этот же
# список знает интерфейс: он заранее предупреждает, что клиенты
# переподключатся.
RESTART_FIELDS = frozenset({
    "address", "listen_port", "mtu",
    "jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
    "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5",
})


@router.put("", response_model=ServerRead)
def update_server(
    payload: ServerUpdate,
    db: Session = Depends(get_db),
    _admin: str = Depends(get_current_admin),
):
    server = config_sync.get_server(db)
    updates = payload.model_dump(exclude_unset=True)

    # Дополнительные протоколы слушают свои порты: совпадение с ними не даст
    # подняться одному из интерфейсов.
    new_port = updates.get("listen_port")
    if new_port is not None:
        for tunnel in config_sync.get_tunnels(db):
            if tunnel.listen_port == new_port:
                raise HTTPException(
                    status_code=400,
                    detail=f"Порт {new_port} уже занят протоколом на интерфейсе {tunnel.interface_name}",
                )

    # Валидируем ссылку каскада ДО сохранения, чтобы в БД не осела заведомо
    # нерабочая настройка молча (cascade.sync() при apply просто выключил бы
    # каскад, ошибку админ увидел бы не сразу).
    cascade_enabled = updates.get("cascade_enabled", server.cascade_enabled)
    cascade_url = updates.get("cascade_vless_url", server.cascade_vless_url)
    if cascade_enabled and cascade_url:
        try:
            cascade.parse_vless_url(cascade_url)
        except cascade.VlessParseError as exc:
            raise HTTPException(status_code=400, detail=f"Ссылка каскада: {exc}") from exc

    changed = {f for f, v in updates.items() if getattr(server, f) != v}
    for field, value in updates.items():
        setattr(server, field, value)
    # Повторное сохранение адреса релея - способ принять его новый
    # сертификат: забываем отпечаток, при следующей синхронизации запомнится.
    if "cascade_sync_url" in updates:
        server.cascade_sync_cert_pin = None
    db.add(server)
    db.commit()
    db.refresh(server)
    relays.pull_primary(db, server)

    # Сохранение сразу применяется к живому интерфейсу, иначе БД и
    # реальный интерфейс расходятся молча — так однажды уже потерялась
    # настройка MTU. Перезапуск (обрыв всех клиентов на несколько секунд)
    # только когда он действительно нужен: адрес, порт, MTU и маскировку
    # `awg syncconf` на лету не применяет. DNS и публичный адрес влияют лишь
    # на клиентские конфиги, а каскад и внешний интерфейс — на xray и
    # правила, которые переставляются без перезапуска туннеля. Раньше
    # перезапуск был на каждое сохранение, даже на смену токена релея.
    restart = bool(changed & RESTART_FIELDS)
    # MTU у дополнительных протоколов общий с основным.
    restart_tunnels = frozenset(t.protocol for t in config_sync.get_tunnels(db)) if "mtu" in changed else frozenset()
    config_sync.apply_current_config(db, restart=restart, restart_tunnels=restart_tunnels)
    db.refresh(server)
    return server


@router.post("/randomize-obfuscation", response_model=ServerRead)
def randomize_obfuscation(db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    """
    Пересоздаёт Jc/Jmin/Jmax/S1-S4/H1-H4 и ключ защиты заголовков 3.1
    сервера. Это общие параметры
    интерфейса (см. models.Peer — у пиров своих полей обфускации нет,
    они всегда берутся из ServerConfig при генерации клиентского конфига),
    поэтому раскатывать их отдельно на записи Peer не нужно и не имеет
    смысла: такого столбца в таблице peers нет, setattr на смапленную
    ORM-модель тут был мёртвым кодом (значение просто не сохранялось).

    Обновлённые значения сразу применяются к живому интерфейсу — иначе
    все уже выданные конфиги перестанут проходить рукопожатие, а никто
    не поймёт почему, пока кто-то явно не нажмёт "применить".
    """
    server = config_sync.get_server(db)
    profile = random_obfuscation_profile()
    for field, value in profile.items():
        setattr(server, field, value)
    db.add(server)
    db.commit()
    db.refresh(server)

    config_sync.apply_current_config(db, restart=True)
    return server


@router.post("/apply", response_model=ApplyResult)
def apply_server_config(db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    from .. import awg_manager

    result = config_sync.apply_current_config(db)
    return ApplyResult(ok=result.ok, message=result.output, live_management_available=awg_manager.tools_available())


@router.post("/restart", response_model=ApplyResult)
def restart_server_interface(db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    from .. import awg_manager

    # Кнопка «перезапустить» — на случай, когда что-то повисло, поэтому
    # перезапускаем всё, включая дополнительные протоколы.
    everything = frozenset(t.protocol for t in config_sync.get_tunnels(db))
    result = config_sync.apply_current_config(db, restart=True, restart_tunnels=everything)
    return ApplyResult(ok=result.ok, message=result.output, live_management_available=awg_manager.tools_available())


@router.post("/cascade/sync", response_model=CascadeStatus)
def cascade_sync_now(db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    """Синхронизация по кнопке: не ждать фонового цикла, когда только что
    поменяли настройки на релее."""
    cascade_sync.sync_once(db)
    return cascade_status(db=db, _admin=_admin)


@router.post("/cascade/verify", response_model=CascadeStatus)
def cascade_verify_now(db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    """Проба трафика через каскад прямо сейчас. Фоновая идёт раз в пять
    минут — слишком долго, чтобы после включения каскада понять, работает ли
    он."""
    server = config_sync.get_server(db)
    if server.cascade_enabled:
        cascade.verify_now()
    return cascade_status(db=db, _admin=_admin)


def _relay_status(relay: CascadeRelay, active_host: str | None) -> RelayStatus:
    params: dict = {}
    if (relay.vless_url or "").strip():
        try:
            params = cascade.parse_vless_url(relay.vless_url)
        except cascade.VlessParseError:
            params = {}
    host = params.get("host")
    return RelayStatus(
        id=relay.id,
        primary=relay.position == 0,
        host=host or cascade_sync.host_of(relay.sync_url) or None,
        port=params.get("port"),
        sni=params.get("sni"),
        label=params.get("label") or None,
        sync_enabled=bool((relay.sync_url or "").strip()),
        sync_error=relay.sync_error,
        synced_at=relay.synced_at,
        version=relay.relay_version,
        active=bool(host) and host == active_host,
    )


@router.post("/cascade/relays", response_model=CascadeStatus)
def add_relay(
    payload: RelayCreate,
    db: Session = Depends(get_db),
    _admin: str = Depends(get_current_admin),
):
    """Добавить резервный релей. Основной меняется в настройках сервера."""
    server = config_sync.get_server(db)
    vless_url = payload.vless_url.strip()
    sync_url = payload.sync_url.strip()
    sync_token = payload.sync_token.strip()
    if not vless_url and not sync_url:
        raise HTTPException(status_code=400, detail="Укажите ссылку vless:// или адрес релея с токеном")
    if vless_url:
        try:
            cascade.parse_vless_url(vless_url)
        except cascade.VlessParseError as exc:
            raise HTTPException(status_code=400, detail=f"Ссылка каскада: {exc}") from exc
    if sync_url:
        if not sync_token:
            raise HTTPException(status_code=400, detail="Для синхронизации нужен токен релея")
        try:
            cascade_sync.host_of(cascade_sync.endpoint_base(sync_url))
        except cascade_sync.SyncError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    relays.pull_primary(db, server)
    relays.add_reserve(db, server, vless_url, sync_url, sync_token)
    config_sync.apply_current_config(db)
    return cascade_status(db=db, _admin=_admin)


@router.delete("/cascade/relays/{relay_id}", response_model=CascadeStatus)
def delete_relay(
    relay_id: int,
    db: Session = Depends(get_db),
    _admin: str = Depends(get_current_admin),
):
    server = config_sync.get_server(db)
    relay = next((r for r in server.relays if r.id == relay_id), None)
    if relay is None:
        raise HTTPException(status_code=404, detail="Такого релея нет")
    if relay.position == 0:
        raise HTTPException(status_code=400, detail="Основной релей меняется в настройках каскада")
    server.relays.remove(relay)
    db.add(server)
    db.commit()
    config_sync.apply_current_config(db)
    return cascade_status(db=db, _admin=_admin)


@router.get("/cascade/status", response_model=CascadeStatus)
def cascade_status(db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    server = config_sync.get_server(db)
    stats = cascade.traffic_stats() or {}
    health = cascade.health()
    bird = canary.status()

    # Разбираем сохранённую ссылку, чтобы показать администратору адрес и
    # маскировку, но не uuid и не ключи.
    relay: dict = {}
    if (server.cascade_vless_url or "").strip():
        try:
            relay = cascade.parse_vless_url(server.cascade_vless_url)
        except cascade.VlessParseError:
            relay = {}
    active_host = cascade.active_relay()
    return CascadeStatus(
        enabled=server.cascade_enabled,
        configured=bool(cascade.relay_urls(server)),
        relays=[_relay_status(r, active_host) for r in server.relays],
        all_down=cascade.all_down_mode(server),
        intercept_suspended=cascade.intercept_suspended(server),
        running=cascade.is_running(),
        error=server.cascade_last_error,
        relay_host=relay.get("host"),
        relay_port=relay.get("port"),
        relay_sni=relay.get("sni"),
        relay_label=relay.get("label") or None,
        sync_enabled=bool((server.cascade_sync_url or "").strip()),
        sync_error=server.cascade_sync_error,
        synced_at=server.cascade_synced_at,
        relay_rotation_at=cascade_sync.next_rotation_at,
        verified_ok=health.get("verified_ok"),
        verified_at=health.get("verified_at"),
        verify_error=health.get("verify_error"),
        restarts=health.get("restarts", 0),
        canary_ok=bird["ok"],
        canary_checked_at=bird["checked_at"],
        canary_error=bird["error"],
        canary_stage=bird["stage"],
        canary_exit_ip=bird["exit_ip"],
        canary_duration_ms=bird["duration_ms"],
        canary_speed_bps=bird["speed_bps"],
        uplink=stats.get("uplink", 0),
        downlink=stats.get("downlink", 0),
        intercept_mode=cascade.intercept_mode(),
        intercept_mode_setting=settings.cascade_intercept_mode,
        kernel=platform.release(),
        kernel_supports_tproxy=cascade.kernel_supports_tproxy(),
    )
