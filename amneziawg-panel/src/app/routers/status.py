from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from .. import awg_manager, cascade, config_sync, traffic_history
from ..database import get_db
from ..models import Peer
from ..schemas import LivePeerStatus, StatusResponse, TrafficHistoryPoint
from ..security import get_current_admin
from .peers import ONLINE_THRESHOLD_SECONDS

router = APIRouter()


@router.get("", response_model=StatusResponse)
def get_status(db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    server = config_sync.get_server(db)
    live_status = config_sync.live_status_by_pubkey(server)
    peers = db.query(Peer).all()

    peer_statuses = []
    for peer in peers:
        entry = (live_status or {}).get(peer.public_key)
        is_online = False
        if entry and entry.latest_handshake:
            age = datetime.now(timezone.utc).timestamp() - entry.latest_handshake
            is_online = age < ONLINE_THRESHOLD_SECONDS
        peer_statuses.append(
            LivePeerStatus(
                peer_id=peer.id,
                name=peer.name,
                online=is_online,
                endpoint=entry.endpoint if entry else None,
                latest_handshake=(
                    datetime.fromtimestamp(entry.latest_handshake, tz=timezone.utc)
                    if entry and entry.latest_handshake
                    else None
                ),
                transfer_rx=entry.transfer_rx if entry else 0,
                transfer_tx=entry.transfer_tx if entry else 0,
            )
        )

    return StatusResponse(
        live_management_available=awg_manager.tools_available(),
        interface_name=server.interface_name,
        interface_up=awg_manager.interface_is_up(server.interface_name) if awg_manager.tools_available() else False,
        interface_mtu=awg_manager.interface_mtu(server.interface_name) if awg_manager.tools_available() else None,
        listen_port=server.listen_port,
        peers=peer_statuses,
    )


@router.get("/traffic-history", response_model=list[TrafficHistoryPoint])
def get_traffic_history(_admin: str = Depends(get_current_admin)):
    return traffic_history.get_history()


@router.get("/metrics", response_class=PlainTextResponse)
def metrics(db: Session = Depends(get_db), _admin: str = Depends(get_current_admin)):
    """
    Метрики в формате Prometheus.

    Нужны, чтобы за сервером можно было следить снаружи, а не заходя
    глазами в панель: до сих пор единственным способом узнать, что каскад
    встал, было открыть страницу и посмотреть. Скрапер ходит сюда с тем же
    Bearer-токеном (в Prometheus это bearer_token в job).
    """
    server = config_sync.get_server(db)
    live = config_sync.live_status_by_pubkey(server) or {}
    peers = db.query(Peer).all()

    now = datetime.now(timezone.utc).timestamp()
    online = sum(
        1 for peer in peers
        if (entry := live.get(peer.public_key)) is not None
        and entry.latest_handshake
        and now - entry.latest_handshake < ONLINE_THRESHOLD_SECONDS
    )
    rx = sum(e.transfer_rx for e in live.values())
    tx = sum(e.transfer_tx for e in live.values())

    stats = cascade.traffic_stats() or {}
    health = cascade.health()
    verified = health.get("verified_ok")

    lines = [
        "# HELP noisefloor_interface_up Поднят ли интерфейс туннеля",
        "# TYPE noisefloor_interface_up gauge",
        f"noisefloor_interface_up {int(awg_manager.interface_is_up(server.interface_name))}",
        "# HELP noisefloor_peers_total Всего клиентов в панели",
        "# TYPE noisefloor_peers_total gauge",
        f"noisefloor_peers_total {len(peers)}",
        "# HELP noisefloor_peers_online Клиенты с недавним рукопожатием",
        "# TYPE noisefloor_peers_online gauge",
        f"noisefloor_peers_online {online}",
        "# HELP noisefloor_interface_rx_bytes_total Принято сервером от клиентов",
        "# TYPE noisefloor_interface_rx_bytes_total counter",
        f"noisefloor_interface_rx_bytes_total {rx}",
        "# HELP noisefloor_interface_tx_bytes_total Отправлено сервером клиентам",
        "# TYPE noisefloor_interface_tx_bytes_total counter",
        f"noisefloor_interface_tx_bytes_total {tx}",
        "# HELP noisefloor_cascade_enabled Включён ли каскад в настройках",
        "# TYPE noisefloor_cascade_enabled gauge",
        f"noisefloor_cascade_enabled {int(bool(server.cascade_enabled))}",
        "# HELP noisefloor_cascade_running Жив ли процесс xray каскада",
        "# TYPE noisefloor_cascade_running gauge",
        f"noisefloor_cascade_running {int(cascade.is_running())}",
        "# HELP noisefloor_cascade_verified Прошла ли последняя проба трафика через каскад (-1 если проверки ещё не было)",
        "# TYPE noisefloor_cascade_verified gauge",
        f"noisefloor_cascade_verified {-1 if verified is None else int(verified)}",
        "# HELP noisefloor_cascade_restarts_total Сколько раз супервизор поднимал упавший xray",
        "# TYPE noisefloor_cascade_restarts_total counter",
        f"noisefloor_cascade_restarts_total {health.get('restarts', 0)}",
        "# HELP noisefloor_cascade_uplink_bytes_total Отправлено через каскад",
        "# TYPE noisefloor_cascade_uplink_bytes_total counter",
        f"noisefloor_cascade_uplink_bytes_total {stats.get('uplink', 0)}",
        "# HELP noisefloor_cascade_downlink_bytes_total Получено через каскад",
        "# TYPE noisefloor_cascade_downlink_bytes_total counter",
        f"noisefloor_cascade_downlink_bytes_total {stats.get('downlink', 0)}",
    ]
    return "\n".join(lines) + "\n"
