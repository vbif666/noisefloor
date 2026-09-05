"""
Действия при первом запуске: создаём администратора и запись ServerConfig,
если их ещё нет в базе.
"""
from __future__ import annotations

import secrets
import socket

from sqlalchemy.orm import Session

from . import crypto
from .config import DATA_DIR, settings
from .models import AdminUser, ServerConfig
from .obfuscation import random_obfuscation_profile
from .security import hash_password


def _detect_public_ip() -> str:
    """
    Пытается определить публичный IP сервера, чтобы не оставлять
    endpoint_host пустым (пустой endpoint_host — источник реального
    прод-инцидента: сгенерированные клиентские конфиги указывали на
    старый/чужой сервер, потому что поле никогда не заполнялось).

    Не открывает реального соединения — UDP-сокет к 8.8.8.8:80 только
    заставляет ОС выбрать исходящий адрес по таблице маршрутизации,
    пакеты никуда не отправляются. Работает даже без интернета внутри
    приватной сети, если у сервера один маршрутизируемый адрес.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        if ip and not ip.startswith(("127.", "169.254.")):
            return ip
    except OSError:
        pass
    return ""


def ensure_admin_user(db: Session) -> None:
    existing = db.query(AdminUser).first()
    if existing:
        return

    password = settings.admin_password
    generated = False
    if not password:
        password = secrets.token_urlsafe(12)
        generated = True

    admin = AdminUser(username=settings.admin_username, password_hash=hash_password(password))
    db.add(admin)
    db.commit()

    if generated:
        notice_path = DATA_DIR / "INITIAL_ADMIN_PASSWORD.txt"
        notice_path.write_text(
            "Логин администратора панели AmneziaWG:\n"
            f"  Пользователь: {settings.admin_username}\n"
            f"  Пароль:       {password}\n\n"
            "Смените пароль (или задайте ADMIN_PASSWORD в .env и перезапустите) "
            "и удалите этот файл после того, как сохранили пароль в надёжном месте.\n"
        )
        notice_path.chmod(0o600)
        print("=" * 72)
        print("Создан администратор панели при первом запуске:")
        print(f"  Пользователь: {settings.admin_username}")
        print(f"  Пароль:       {password}")
        print(f"  (также сохранено в {notice_path})")
        print("=" * 72)


def ensure_server_config(db: Session) -> None:
    existing = db.query(ServerConfig).first()
    if existing:
        # Подстраховка для уже существующих БД (например, склонированных
        # с другого сервера): если endpoint_host пуст, клиентские конфиги
        # будут либо нерабочими ("YOUR_SERVER_HOST_OR_IP"), либо, что хуже,
        # молча указывать на адрес, с которого сняли снапшот/клон.
        if not existing.endpoint_host:
            detected = _detect_public_ip()
            if detected:
                existing.endpoint_host = detected
                db.add(existing)
                db.commit()
        return

    priv, pub = crypto.generate_keypair()
    server = ServerConfig(
        interface_name=settings.awg_interface,
        private_key=priv,
        public_key=pub,
        address=settings.default_server_address,
        listen_port=settings.default_listen_port,
        dns=settings.default_dns,
        endpoint_host=_detect_public_ip(),
        egress_interface=settings.egress_interface,
        i1="", i2="", i3="", i4="", i5="",
        **random_obfuscation_profile(),
    )
    db.add(server)
    db.commit()


def run(db: Session) -> None:
    ensure_admin_user(db)
    ensure_server_config(db)
