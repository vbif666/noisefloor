"""
Запасной вход: VLESS+REALITY по TCP на том xray, что уже работает для каскада.

Для сетей, где режут UDP и AmneziaWG не поднимается. Клиенты отдельные: у них нет
ключей WireGuard и адреса в подсети, поэтому своя таблица, а не строка в peers. Обе
таблицы новые, старые не меняются, и откат на прошлую версию просто их не заметит.

Работает только при запущенном каскаде: своего процесса у входа нет. Без включённых
клиентов порт не занимаем.
"""
from __future__ import annotations

import base64
import re
import secrets
import socket
import uuid as uuid_module
from urllib.parse import quote, urlencode

from sqlalchemy.orm import Session, object_session
from sqlalchemy.orm.exc import UnmappedInstanceError

from . import crypto
from .config import settings
from .models import FallbackClient, FallbackConfig

FLOW = "xtls-rprx-vision"
DEFAULT_SNI = "dl.google.com"
DEFAULT_DEST = "dl.google.com:443"
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def generate_reality_keys() -> tuple[str, str]:
    """(приватный, публичный) для REALITY: тот же X25519, что у WireGuard, но в
    base64url без выравнивания."""
    def recode(key: str) -> str:
        return base64.urlsafe_b64encode(base64.b64decode(key)).decode("ascii").rstrip("=")

    private, public = crypto.generate_keypair()
    return recode(private), recode(public)


def get_config(db: Session) -> FallbackConfig:
    """Строка с настройками. Ключи создаются при первом обращении."""
    config = db.query(FallbackConfig).first()
    if config is None:
        private, public = generate_reality_keys()
        config = FallbackConfig(enabled=False, port=settings.vless_port, sni=DEFAULT_SNI, dest=DEFAULT_DEST,
                                private_key=private, public_key=public, short_id=secrets.token_hex(8))
        db.add(config)
        db.commit()
    return config


def new_client(name: str) -> FallbackClient:
    return FallbackClient(name=name, uuid=str(uuid_module.uuid4()), enabled=True)


def valid_dest(dest: str) -> bool:
    host, _, port = dest.rpartition(":")
    return bool(HOSTNAME_RE.match(host)) and port.isdigit() and 1 <= int(port) <= 65535


def params(server) -> dict | None:
    """То, что нужно конфигу xray, или None, если входа быть не должно."""
    try:
        db = object_session(server)
    except UnmappedInstanceError:
        return None
    if db is None:
        return None
    config = db.query(FallbackConfig).first()
    if config is None or not config.enabled:
        return None
    clients = [c.uuid for c in db.query(FallbackClient).filter(FallbackClient.enabled.is_(True))
               .order_by(FallbackClient.id).all()]
    if not clients:
        return None
    return {"port": config.port, "sni": config.sni, "dest": config.dest,
            "private_key": config.private_key, "short_id": config.short_id, "clients": clients}


def port_free(port: int) -> bool:
    """Занятый порт уронил бы весь xray, а с ним каскад основных клиентов."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
        except OSError:
            return False
    return True


# 443 часто держит веб-сервер хоста (nginx на 147). Тогда вход переезжает сюда:
# тоже привычный для HTTPS порт, и REALITY на нём выглядит естественно.
DEFAULT_PORT = 443
ALT_PORT = 8443


def busy_message(port: int) -> str:
    if port == DEFAULT_PORT:
        return (f"VLESS не запущен: порты {DEFAULT_PORT} и {ALT_PORT}/tcp заняты другими программами — "
                "укажите свободный порт")
    return f"VLESS не запущен: порт {port}/tcp занят"


def move_off_busy_port(db: Session, own_ports: set) -> bool:
    """443 занят чужой программой, а 8443 свободен: перевести вход на 8443.

    Сохраняется в базе, а не подменяется на лету: порт стоит в ссылке клиента,
    и ссылки должны сразу выдаваться с тем портом, который реально слушается.
    Порт, который держит наш же xray, занятым не считается."""
    config = db.query(FallbackConfig).first()
    if config is None or not config.enabled or config.port != DEFAULT_PORT:
        return False
    if DEFAULT_PORT in own_ports or port_free(DEFAULT_PORT):
        return False
    if ALT_PORT not in own_ports and not port_free(ALT_PORT):
        return False
    config.port = ALT_PORT
    config.port_notice = (
        f"Порт {DEFAULT_PORT}/tcp занят другой программой (например, веб-сервером), поэтому VLESS "
        f"автоматически переведён на {ALT_PORT}/tcp. Откройте {ALT_PORT}/tcp в фаерволе хостинга. "
        f"Ссылки, выданные раньше с портом {DEFAULT_PORT}, нужно выдать заново."
    )
    db.commit()
    return True


def client_link(config: FallbackConfig, client: FallbackClient, host: str) -> str:
    host = host or "YOUR_SERVER_HOST_OR_IP"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    query = urlencode({"type": "tcp", "security": "reality", "encryption": "none", "flow": FLOW,
                       "sni": config.sni, "fp": "chrome", "pbk": config.public_key, "sid": config.short_id})
    return f"vless://{client.uuid}@{host}:{config.port}?{query}#{quote(client.name, safe='')}"
