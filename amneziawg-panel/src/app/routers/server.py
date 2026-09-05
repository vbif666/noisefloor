from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import cascade, config_sync
from ..database import get_db
from ..obfuscation import random_obfuscation_profile
from ..schemas import ApplyResult, CascadeStatus, ServerRead, ServerUpdate
from ..security import get_current_admin

router = APIRouter()


@router.get("", response_model=ServerRead)
def read_server(db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    return config_sync.get_server(db)


@router.put("", response_model=ServerRead)
def update_server(
    payload: ServerUpdate,
    db: Session = Depends(get_db),
    _admin: str = Depends(get_current_admin),
):
    server = config_sync.get_server(db)
    updates = payload.model_dump(exclude_unset=True)

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

    for field, value in updates.items():
        setattr(server, field, value)
    db.add(server)
    db.commit()
    db.refresh(server)

    # Поля интерфейса (адрес/порт/MTU/DNS/обфускация и т.д.) должны сразу
    # применяться к живому awg0, иначе БД и реальный интерфейс расходятся
    # молча — ровно так один раз уже потерялась настройка MTU. restart=True,
    # потому что часть этих полей (адрес, MTU, порт) `awg syncconf` не
    # применяет на лету, нужен полноценный down/up.
    config_sync.apply_current_config(db, restart=True)
    return server


@router.post("/randomize-obfuscation", response_model=ServerRead)
def randomize_obfuscation(db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    """
    Пересоздаёт Jc/Jmin/Jmax/S1-S4/H1-H4 сервера. Это общие параметры
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

    result = config_sync.apply_current_config(db, restart=True)
    return ApplyResult(ok=result.ok, message=result.output, live_management_available=awg_manager.tools_available())


@router.post("/cascade/sync", response_model=CascadeStatus)
def cascade_sync_now(db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    """Синхронизация по кнопке: не ждать фонового цикла, когда только что
    поменяли настройки на релее."""
    from .. import cascade_sync

    cascade_sync.sync_once(db)
    return cascade_status(db=db, _admin=_admin)


@router.get("/cascade/status", response_model=CascadeStatus)
def cascade_status(db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    server = config_sync.get_server(db)
    stats = cascade.traffic_stats() or {}
    health = cascade.health()
    return CascadeStatus(
        enabled=server.cascade_enabled,
        configured=bool((server.cascade_vless_url or "").strip()),
        running=cascade.is_running(),
        error=server.cascade_last_error,
        sync_enabled=bool((server.cascade_sync_url or "").strip()),
        sync_error=server.cascade_sync_error,
        synced_at=server.cascade_synced_at,
        verified_ok=health.get("verified_ok"),
        verified_at=health.get("verified_at"),
        verify_error=health.get("verify_error"),
        restarts=health.get("restarts", 0),
        uplink=stats.get("uplink", 0),
        downlink=stats.get("downlink", 0),
    )
