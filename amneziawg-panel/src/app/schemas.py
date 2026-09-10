from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field


def _assume_utc(value: datetime | None) -> datetime | None:
    """Проставить UTC времени, пришедшему из БД без часового пояса.

    SQLite зону не хранит: записанное как UTC читается обратно «голым».
    Браузер строку без зоны понимает как МЕСТНОЕ время, поэтому только что
    выполненная синхронизация показывалась как «3 часа назад» на UTC+3.
    Чиним на выходе из API — тогда любой потребитель, не только наш
    интерфейс, получает однозначную метку времени."""
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


# Время, которое пришло из базы и обязано уехать наружу с зоной.
UtcDatetime = Annotated[datetime, AfterValidator(_assume_utc)]


# --- Auth ---

class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class MeResponse(BaseModel):
    username: str


# --- Server / interface ---

class ServerRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    interface_name: str
    public_key: str
    address: str
    listen_port: int
    dns: str
    mtu: int | None
    endpoint_host: str
    egress_interface: str
    cascade_enabled: bool
    cascade_vless_url: str
    cascade_last_error: str | None
    split_ru_direct: bool = False
    cascade_sync_url: str = ""
    cascade_sync_token: str = ""
    cascade_sync_error: str | None = None
    cascade_synced_at: UtcDatetime | None = None
    jc: int
    jmin: int
    jmax: int
    s1: int
    s2: int
    s3: int
    s4: int
    h1: str
    h2: str
    h3: str
    h4: str
    i1: str
    i2: str
    i3: str
    i4: str
    i5: str
    last_apply_status: str | None
    last_apply_error: str | None
    last_applied_at: UtcDatetime | None
    updated_at: UtcDatetime


class ServerUpdate(BaseModel):
    address: str | None = None
    listen_port: int | None = Field(default=None, ge=1, le=65535)
    dns: str | None = None
    mtu: int | None = None
    endpoint_host: str | None = None
    egress_interface: str | None = None
    cascade_enabled: bool | None = None
    cascade_vless_url: str | None = None
    split_ru_direct: bool | None = None
    cascade_sync_url: str | None = None
    cascade_sync_token: str | None = None
    jc: int | None = Field(default=None, ge=0, le=128)
    jmin: int | None = Field(default=None, ge=0)
    jmax: int | None = Field(default=None, ge=0)
    s1: int | None = Field(default=None, ge=0)
    s2: int | None = Field(default=None, ge=0)
    s3: int | None = Field(default=None, ge=0)
    s4: int | None = Field(default=None, ge=0)
    h1: str | None = None
    h2: str | None = None
    h3: str | None = None
    h4: str | None = None
    i1: str | None = None
    i2: str | None = None
    i3: str | None = None
    i4: str | None = None
    i5: str | None = None


class ApplyResult(BaseModel):
    ok: bool
    message: str
    live_management_available: bool


class CascadeStatus(BaseModel):
    enabled: bool
    configured: bool  # ссылка указана и разобралась без ошибок
    running: bool  # процесс xray сейчас жив
    error: str | None
    uplink: int = 0
    downlink: int = 0
    # Ниже — итог реальной пробы наружу через каскад. Отличать это от
    # running обязательно: процесс может быть жив, а трафик не идти.
    verified_ok: bool | None = None  # None — проверки ещё не было
    verified_at: UtcDatetime | None = None
    verify_error: str | None = None
    restarts: int = 0  # сколько раз супервизор поднимал упавший xray
    # Синхронизация параметров с релеем
    sync_enabled: bool = False
    sync_error: str | None = None
    synced_at: UtcDatetime | None = None
    # Куда и подо что настроен каскад — без uuid и ключей: панель показывает
    # это администратору, а держать перед глазами готовый доступ к релею
    # незачем, тем более что панель работает без TLS.
    relay_host: str | None = None
    relay_port: int | None = None
    relay_sni: str | None = None
    relay_label: str | None = None


# --- Peers ---

class PeerCreate(BaseModel):
    # Без \r\n: имя пира попадает в awg0.conf как комментарий
    # "# {peer.name}" — перевод строки в значении дал бы возможность
    # вставить в конфиг произвольную "строку" (директиву).
    name: str = Field(min_length=1, max_length=128, pattern=r"^[^\r\n]+$")
    allowed_ips_client: str = "0.0.0.0/0, ::/0"
    dns_override: str | None = None
    persistent_keepalive: int = Field(default=25, ge=0, le=3600)
    note: str | None = None


class PeerUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128, pattern=r"^[^\r\n]+$")
    enabled: bool | None = None
    allowed_ips_client: str | None = None
    dns_override: str | None = None
    persistent_keepalive: int | None = Field(default=None, ge=0, le=3600)
    note: str | None = None


class PeerRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    public_key: str
    address: str
    allowed_ips_client: str
    dns_override: str | None
    persistent_keepalive: int
    enabled: bool
    note: str | None
    created_at: UtcDatetime

    # живой статус (заполняется отдельно, не хранится в БД)
    online: bool = False
    latest_handshake: UtcDatetime | None = None
    transfer_rx: int = 0
    transfer_tx: int = 0


class PeerWithConfig(PeerRead):
    config_text: str


# --- Status ---

class LivePeerStatus(BaseModel):
    peer_id: int
    name: str
    online: bool
    endpoint: str | None
    latest_handshake: UtcDatetime | None
    transfer_rx: int
    transfer_tx: int


class StatusResponse(BaseModel):
    live_management_available: bool
    interface_name: str
    interface_up: bool
    interface_mtu: int | None
    listen_port: int | None
    peers: list[LivePeerStatus]


class TrafficHistoryPoint(BaseModel):
    t: str
    iface_rx: int
    iface_tx: int
    cascade_enabled: bool
    cascade_running: bool
    cascade_uplink: int
    cascade_downlink: int


# --- Резервные копии ---

class BackupInfo(BaseModel):
    name: str
    size: int
    created_at: UtcDatetime
    encrypted: bool


# --- Обновление бинарников AmneziaWG ---

class UpdateComponent(BaseModel):
    name: str
    current: str | None
    latest: str | None
    update_available: bool


class UpdateCheckResponse(BaseModel):
    checked_ok: bool
    error: str | None
    update_available: bool
    components: list[UpdateComponent]


class UpdateApplyResponse(BaseModel):
    ok: bool
    output: str
