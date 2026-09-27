from __future__ import annotations

import urllib.parse

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from .. import awg_config, config_sync, crypto
from ..database import get_db
from ..ip_pool import next_available_ip
from ..models import PROTOCOL_AWG2, Peer
from ..qr import config_to_png
from ..schemas import PeerCreate, PeerRead, PeerUpdate, PeerWithConfig
from ..security import get_current_admin

router = APIRouter()

# WireGuard/AmneziaWG перекладывают ключи не реже, чем раз в REJECT_AFTER_TIME
# (180с). Если рукопожатие было позже — считаем пира активным прямо сейчас,
# а не просто "хоть раз подключался".
ONLINE_THRESHOLD_SECONDS = 180


def _to_read(peer: Peer, live_status: dict | None) -> PeerRead:
    data = PeerRead.model_validate(peer)
    status_entry = (live_status or {}).get(peer.public_key)
    if status_entry is not None:
        if status_entry.latest_handshake:
            data.latest_handshake = datetime.fromtimestamp(status_entry.latest_handshake, tz=timezone.utc)
            age = datetime.now(timezone.utc).timestamp() - status_entry.latest_handshake
            data.online = age < ONLINE_THRESHOLD_SECONDS
        data.transfer_rx = status_entry.transfer_rx
        data.transfer_tx = status_entry.transfer_tx
    return data


def _client_config(db: Session, peer: Peer, server) -> str:
    """Конфиг клиента с ключом, портом и обфускацией его интерфейса."""
    protocol = peer.protocol or PROTOCOL_AWG2
    tunnel = None if protocol == PROTOCOL_AWG2 else config_sync.get_tunnel(db, protocol)
    return awg_config.client_config(peer, server, tunnel)


def _get_peer_or_404(db: Session, peer_id: int) -> Peer:
    peer = db.get(Peer, peer_id)
    if peer is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Пир не найден")
    return peer


@router.get("", response_model=list[PeerRead])
def list_peers(db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    server = config_sync.get_server(db)
    live_status = config_sync.live_status_by_pubkey(server)
    peers = db.query(Peer).order_by(Peer.created_at.asc()).all()
    return [_to_read(peer, live_status) for peer in peers]


@router.post("", response_model=PeerWithConfig, status_code=status.HTTP_201_CREATED)
def create_peer(payload: PeerCreate, db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    server = config_sync.get_server(db)

    subnet = server.address
    if payload.protocol != PROTOCOL_AWG2:
        tunnel = config_sync.get_tunnel(db, payload.protocol)
        if tunnel is None or not tunnel.enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Этот протокол выключен — включите его на вкладке «Сервер», блок «Протоколы»",
            )
        subnet = tunnel.address

    # Занятые адреса — по всем клиентам и всем интерфейсам: подсети разные,
    # но лишняя проверка дешевле пересечения, если их когда-то сдвинут.
    used_ips = {a for (a,) in db.query(Peer.address).all()}
    used_ips = {ip.split("/")[0] for ip in used_ips}
    used_ips.add(server.address.split("/")[0])
    used_ips.update(t.address.split("/")[0] for t in config_sync.get_tunnels(db))
    try:
        address = next_available_ip(subnet, used_ips)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    priv, pub = crypto.generate_keypair()
    peer = Peer(
        name=payload.name,
        private_key=priv,
        public_key=pub,
        preshared_key=crypto.generate_preshared_key(),
        address=address,
        allowed_ips_client=payload.allowed_ips_client,
        dns_override=payload.dns_override,
        persistent_keepalive=payload.persistent_keepalive,
        enabled=True,
        note=payload.note,
        protocol=payload.protocol,
    )
    db.add(peer)
    db.commit()
    db.refresh(peer)

    config_sync.apply_current_config(db)  # best-effort, ошибки не блокируют создание

    data = _to_read(peer, None)
    return PeerWithConfig(**data.model_dump(), config_text=_client_config(db, peer, server))


@router.get("/{peer_id}", response_model=PeerWithConfig)
def read_peer(peer_id: int, db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    server = config_sync.get_server(db)
    peer = _get_peer_or_404(db, peer_id)
    live_status = config_sync.live_status_by_pubkey(server)
    data = _to_read(peer, live_status)
    return PeerWithConfig(**data.model_dump(), config_text=_client_config(db, peer, server))


@router.patch("/{peer_id}", response_model=PeerRead)
def update_peer(
    peer_id: int,
    payload: PeerUpdate,
    db: Session = Depends(get_db),
    _admin: str = Depends(get_current_admin),
):
    peer = _get_peer_or_404(db, peer_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(peer, field, value)
    db.add(peer)
    db.commit()
    db.refresh(peer)

    config_sync.apply_current_config(db)

    server = config_sync.get_server(db)
    live_status = config_sync.live_status_by_pubkey(server)
    return _to_read(peer, live_status)


@router.post("/{peer_id}/regenerate-keys", response_model=PeerWithConfig)
def regenerate_peer_keys(peer_id: int, db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    peer = _get_peer_or_404(db, peer_id)
    priv, pub = crypto.generate_keypair()
    peer.private_key = priv
    peer.public_key = pub
    peer.preshared_key = crypto.generate_preshared_key()
    db.add(peer)
    db.commit()
    db.refresh(peer)

    config_sync.apply_current_config(db)

    server = config_sync.get_server(db)
    data = _to_read(peer, None)
    return PeerWithConfig(**data.model_dump(), config_text=_client_config(db, peer, server))


@router.delete("/{peer_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_peer(peer_id: int, db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    peer = _get_peer_or_404(db, peer_id)
    db.delete(peer)
    db.commit()
    config_sync.apply_current_config(db)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{peer_id}/config")
def download_peer_config(peer_id: int, db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    server = config_sync.get_server(db)
    peer = _get_peer_or_404(db, peer_id)
    text = _client_config(db, peer, server)
    safe_name = "".join(c for c in peer.name if c.isascii() and (c.isalnum() or c in "-_")) or "peer"
    utf8_name = urllib.parse.quote(peer.name + ".conf")
    disposition = "attachment; filename=\"" + safe_name + ".conf\"; filename*=UTF-8''" + utf8_name
    return Response(
        content=text,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": disposition},
    )


@router.get("/{peer_id}/qrcode")
def peer_qrcode(peer_id: int, db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    server = config_sync.get_server(db)
    peer = _get_peer_or_404(db, peer_id)
    text = _client_config(db, peer, server)
    png_bytes = config_to_png(text)
    return Response(content=png_bytes, media_type="image/png")
