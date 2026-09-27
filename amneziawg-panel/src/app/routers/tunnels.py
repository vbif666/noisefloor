"""
Дополнительные протоколы: AmneziaWG 1.x и обычный WireGuard.

Каждый — отдельный интерфейс со своим UDP-портом, ключами и подсетью (см.
models.Tunnel). Здесь их включают, двигают порт и подсеть и, для AWG 1.x,
меняют профиль обфускации.
"""
from __future__ import annotations

import errno
import ipaddress
import socket

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import awg_manager, config_sync
from ..database import get_db
from ..models import PROTOCOL_AWG1, PROTOCOLS, Peer, Tunnel
from ..obfuscation import random_awg1_profile
from ..schemas import TunnelRead, TunnelUpdate
from ..security import get_current_admin

router = APIRouter()

_OBFS_FIELDS = ("jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4")
_UINT32_MAX = 2**32 - 1


def _bad(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


def _to_read(db: Session, tunnel: Tunnel) -> TunnelRead:
    data = TunnelRead.model_validate(tunnel)
    if awg_manager.tools_available():
        data.interface_up = awg_manager.interface_is_up(tunnel.interface_name)
    data.peers_total = db.query(Peer).filter(Peer.protocol == tunnel.protocol).count()
    return data


def _get_or_404(db: Session, protocol: str) -> Tunnel:
    tunnel = config_sync.get_tunnel(db, protocol) if protocol in PROTOCOLS else None
    if tunnel is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Такого протокола нет")
    return tunnel


def udp_port_busy(port: int) -> bool:
    """Занят ли UDP-порт на хосте. Панель работает в network_mode: host,
    поэтому пробная привязка здесь — это привязка на самом сервере."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.bind(("0.0.0.0", port))
        except OSError as exc:
            return exc.errno == errno.EADDRINUSE
    return False


def validate_address(db: Session, tunnel: Tunnel, address: str) -> str:
    try:
        iface = ipaddress.ip_interface(address.strip())
    except ValueError as exc:
        raise _bad(f"Подсеть «{address}» не разобрать — нужно вида 10.13.14.1/24") from exc
    if iface.version != 4:
        raise _bad("Подсеть туннеля — только IPv4")
    if iface.network.prefixlen > 30:
        raise _bad("Подсеть слишком мала: нужно хотя бы /30")
    if iface.ip == iface.network.network_address:
        raise _bad("Адрес сервера не может совпадать с адресом сети — например, 10.13.14.1/24")

    server = config_sync.get_server(db)
    others = [("основного интерфейса", server.address)] + [
        (t.interface_name, t.address) for t in config_sync.get_tunnels(db) if t.id != tunnel.id
    ]
    for label, other in others:
        try:
            other_net = ipaddress.ip_interface(other).network
        except ValueError:
            continue
        if iface.network.overlaps(other_net):
            raise _bad(f"Подсеть {iface.network} пересекается с подсетью {label} ({other_net})")

    if iface.network != ipaddress.ip_interface(tunnel.address).network:
        clients = db.query(Peer).filter(Peer.protocol == tunnel.protocol).count()
        if clients:
            raise _bad(
                f"У протокола уже {clients} клиент(ов) с адресами из старой подсети — "
                "сменить её можно, только удалив их"
            )
    return str(iface)


def validate_port(db: Session, tunnel: Tunnel, port: int) -> None:
    server = config_sync.get_server(db)
    if port == server.listen_port:
        raise _bad(f"Порт {port} уже у основного интерфейса AmneziaWG 2.0")
    for other in config_sync.get_tunnels(db):
        if other.id != tunnel.id and other.listen_port == port:
            raise _bad(f"Порт {port} уже у интерфейса {other.interface_name}")


def validate_obfuscation(values: dict) -> None:
    if values["jmin"] > values["jmax"]:
        raise _bad("Jmin не может быть больше Jmax")
    if values["s1"] + 56 == values["s2"]:
        raise _bad("S1 + 56 не должно равняться S2: Init и Response станут одного размера")
    headers = []
    for field in ("h1", "h2", "h3", "h4"):
        raw = str(values[field]).strip()
        if not raw.isdigit() or not 5 <= int(raw) <= _UINT32_MAX:
            raise _bad(f"{field.upper()} — одно целое число от 5 до {_UINT32_MAX}")
        headers.append(int(raw))
    if len(set(headers)) != 4:
        raise _bad("H1–H4 должны отличаться друг от друга")


@router.get("", response_model=list[TunnelRead])
def list_tunnels(db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    return [_to_read(db, t) for t in config_sync.get_tunnels(db)]


@router.put("/{protocol}", response_model=TunnelRead)
def update_tunnel(
    protocol: str,
    payload: TunnelUpdate,
    db: Session = Depends(get_db),
    _admin: str = Depends(get_current_admin),
):
    tunnel = _get_or_404(db, protocol)
    updates = payload.model_dump(exclude_unset=True)

    if tunnel.protocol != PROTOCOL_AWG1:
        # У обычного WireGuard обфускации нет и быть не может: стандартный
        # клиент с ней не соединится.
        for field in _OBFS_FIELDS:
            updates.pop(field, None)

    if "address" in updates:
        updates["address"] = validate_address(db, tunnel, updates["address"])
    if "listen_port" in updates:
        validate_port(db, tunnel, updates["listen_port"])
    if tunnel.protocol == PROTOCOL_AWG1 and any(f in updates for f in _OBFS_FIELDS):
        validate_obfuscation({f: updates.get(f, getattr(tunnel, f)) for f in _OBFS_FIELDS})

    enabling = updates.get("enabled", tunnel.enabled)
    port = updates.get("listen_port", tunnel.listen_port)
    already_listening = (
        tunnel.enabled
        and port == tunnel.listen_port
        and awg_manager.tools_available()
        and awg_manager.interface_is_up(tunnel.interface_name)
    )
    if enabling and awg_manager.tools_available() and not already_listening and udp_port_busy(port):
        raise _bad(f"UDP-порт {port} на сервере уже занят другой программой — выберите другой")

    needs_restart = any(
        f in updates and updates[f] != getattr(tunnel, f)
        for f in ("address", "listen_port", *_OBFS_FIELDS)
    )
    for field, value in updates.items():
        setattr(tunnel, field, value)
    db.add(tunnel)
    db.commit()

    config_sync.apply_current_config(
        db, restart_tunnels=frozenset({tunnel.protocol}) if needs_restart else frozenset()
    )
    db.refresh(tunnel)
    return _to_read(db, tunnel)


@router.post("/{protocol}/randomize", response_model=TunnelRead)
def randomize_tunnel(protocol: str, db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    """Новый профиль обфускации AWG 1.x. Все выданные клиентам этого
    протокола конфиги после этого перестают подключаться — их надо
    перевыпустить."""
    tunnel = _get_or_404(db, protocol)
    if tunnel.protocol != PROTOCOL_AWG1:
        raise _bad("Обфускация есть только у AmneziaWG 1.x")
    for field, value in random_awg1_profile().items():
        setattr(tunnel, field, value)
    db.add(tunnel)
    db.commit()
    config_sync.apply_current_config(db, restart_tunnels=frozenset({tunnel.protocol}))
    db.refresh(tunnel)
    return _to_read(db, tunnel)
