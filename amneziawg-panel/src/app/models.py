from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

from .database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AdminUser(Base):
    __tablename__ = "admin_users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=_utcnow)


class ServerConfig(Base):
    """
    Единственная строка (singleton) — настройки локального интерфейса AmneziaWG.
    """

    __tablename__ = "server_config"

    id = Column(Integer, primary_key=True)
    interface_name = Column(String(32), default="awg0", nullable=False)

    private_key = Column(String(64), nullable=False)
    public_key = Column(String(64), nullable=False)

    address = Column(String(64), nullable=False, default="10.13.13.1/24")
    listen_port = Column(Integer, nullable=False, default=51820)
    dns = Column(String(255), default="1.1.1.1")
    mtu = Column(Integer, nullable=True)

    # Публичный адрес/домен, на который будут подключаться клиенты
    endpoint_host = Column(String(255), default="")
    # Интерфейс с выходом в интернет, для NAT (PostUp/PostDown MASQUERADE)
    egress_interface = Column(String(32), default="eth0")

    # --- Каскад: маршрутизация TCP-трафика клиентов через внешний VLESS ---
    # (см. app/cascade.py). Выключено по умолчанию — обычный прямой NAT.
    cascade_enabled = Column(Boolean, default=False, nullable=False)
    cascade_vless_url = Column(Text, default="")
    cascade_last_error = Column(Text, nullable=True)

    # --- Параметры обфускации AmneziaWG 2.0 ---
    jc = Column(Integer, default=6)
    jmin = Column(Integer, default=40)
    jmax = Column(Integer, default=70)
    s1 = Column(Integer, default=0)
    s2 = Column(Integer, default=0)
    s3 = Column(Integer, default=0)
    s4 = Column(Integer, default=0)
    h1 = Column(String(32), default="")
    h2 = Column(String(32), default="")
    h3 = Column(String(32), default="")
    h4 = Column(String(32), default="")
    # Сигнатурные пакеты CPS (необязательные, см. документацию Amnezia)
    i1 = Column(Text, default="")
    i2 = Column(Text, default="")
    i3 = Column(Text, default="")
    i4 = Column(Text, default="")
    i5 = Column(Text, default="")

    # --- Статус последнего применения на живой интерфейс ---
    last_apply_status = Column(String(16), nullable=True)  # "ok" | "error" | None
    last_apply_error = Column(Text, nullable=True)
    last_applied_at = Column(DateTime, nullable=True)

    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class Peer(Base):
    __tablename__ = "peers"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False)

    private_key = Column(String(64), nullable=False)
    public_key = Column(String(64), nullable=False, index=True)
    preshared_key = Column(String(64), nullable=False)

    address = Column(String(64), nullable=False)  # напр. 10.13.13.2/32 — адрес этого клиента
    allowed_ips_client = Column(String(255), default="0.0.0.0/0, ::/0")  # что клиент шлёт в туннель
    dns_override = Column(String(255), nullable=True)
    persistent_keepalive = Column(Integer, default=25)

    enabled = Column(Boolean, default=True, nullable=False)
    note = Column(Text, nullable=True)

    # Параметров обфускации (Jc/Jmin/Jmax/S1-S4/H1-H4/I1-I5) у пира нет:
    # это общие настройки интерфейса, они берутся из ServerConfig и должны
    # совпадать на сервере и у всех клиентов (см. awg_config.client_config).

    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
