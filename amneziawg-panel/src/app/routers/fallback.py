from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from .. import cascade, config_sync, fallback
from ..database import get_db
from ..models import FallbackClient
from ..qr import config_to_png
from ..schemas import FallbackClientCreate, FallbackClientRead, FallbackClientUpdate, FallbackRead, FallbackUpdate
from ..security import get_current_admin

router = APIRouter()


def _client_read(config, client: FallbackClient, host: str) -> FallbackClientRead:
    return FallbackClientRead(id=client.id, name=client.name, enabled=client.enabled,
                              link=fallback.client_link(config, client, host))


def _read(db: Session) -> FallbackRead:
    config = fallback.get_config(db)
    server = config_sync.get_server(db)
    clients = db.query(FallbackClient).order_by(FallbackClient.id).all()
    return FallbackRead(enabled=config.enabled, port=config.port, sni=config.sni, dest=config.dest,
                        cascade_running=cascade.is_running(), listening=cascade.fallback_listening(),
                        warning=cascade.fallback_warning(),
                        clients=[_client_read(config, c, server.endpoint_host) for c in clients])


def _client_or_404(db: Session, client_id: int) -> FallbackClient:
    client = db.get(FallbackClient, client_id)
    if client is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Клиент не найден")
    return client


@router.get("", response_model=FallbackRead)
def get_settings(db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    return _read(db)


@router.put("", response_model=FallbackRead)
def put_settings(body: FallbackUpdate, db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    if body.port in cascade.RESERVED_TCP_PORTS:
        raise HTTPException(status_code=422, detail=f"Порт {body.port} занят самим каскадом")
    if not fallback.HOSTNAME_RE.match(body.sni):
        raise HTTPException(status_code=422, detail="SNI должен быть именем сайта")
    if not fallback.valid_dest(body.dest):
        raise HTTPException(status_code=422, detail="Камуфляжный сайт указывается как имя:порт")
    config = fallback.get_config(db)
    config.enabled, config.port, config.sni, config.dest = body.enabled, body.port, body.sni, body.dest
    db.commit()
    config_sync.apply_current_config(db)
    return _read(db)


@router.post("/clients", response_model=FallbackClientRead, status_code=status.HTTP_201_CREATED)
def create_client(body: FallbackClientCreate, db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    config = fallback.get_config(db)
    client = fallback.new_client(body.name)
    db.add(client)
    db.commit()
    config_sync.apply_current_config(db)
    return _client_read(config, client, config_sync.get_server(db).endpoint_host)


@router.patch("/clients/{client_id}", response_model=FallbackClientRead)
def update_client(client_id: int, body: FallbackClientUpdate, db: Session = Depends(get_db),
                  _admin: str = Depends(get_current_admin)):
    client = _client_or_404(db, client_id)
    client.enabled = body.enabled
    db.commit()
    config_sync.apply_current_config(db)
    return _client_read(fallback.get_config(db), client, config_sync.get_server(db).endpoint_host)


@router.delete("/clients/{client_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_client(client_id: int, db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    db.delete(_client_or_404(db, client_id))
    db.commit()
    config_sync.apply_current_config(db)


@router.get("/clients/{client_id}/qrcode")
def client_qrcode(client_id: int, db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    link = fallback.client_link(fallback.get_config(db), _client_or_404(db, client_id),
                                config_sync.get_server(db).endpoint_host)
    return Response(content=config_to_png(link), media_type="image/png")
