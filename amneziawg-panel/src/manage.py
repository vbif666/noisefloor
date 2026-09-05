#!/usr/bin/env python3
"""
Небольшие административные команды.

Использование:
    python3 manage.py set-admin-password <username> <password>
    python3 manage.py list-admins
    python3 manage.py restart-interface
"""
from __future__ import annotations

import sys

from app.database import Base, SessionLocal, engine
from app.models import AdminUser
from app.security import hash_password


def cmd_set_admin_password(username: str, password: str) -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        user = db.query(AdminUser).filter(AdminUser.username == username).first()
        if user is None:
            user = AdminUser(username=username, password_hash=hash_password(password))
            db.add(user)
            print(f"Создан администратор «{username}».")
        else:
            user.password_hash = hash_password(password)
            print(f"Пароль администратора «{username}» обновлён.")
        db.commit()
    finally:
        db.close()


def cmd_list_admins() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        for user in db.query(AdminUser).all():
            print(f"- {user.username} (создан: {user.created_at})")
    finally:
        db.close()


def cmd_restart_interface() -> None:
    """
    Переприменяет текущий конфиг из БД на живой интерфейс (down/up).
    Используется автообновлением бинарников awg — после подмены
    amneziawg-go/awg на диске старый процесс интерфейса нужно перезапустить,
    чтобы он подхватил новый бинарник.
    """
    from app import config_sync

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        result = config_sync.apply_current_config(db, restart=True)
        print(f"restart-interface: ok={result.ok} output={result.output}")
        if not result.ok:
            sys.exit(1)
    finally:
        db.close()


def main() -> None:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(1)

    command, rest = args[0], args[1:]
    if command == "set-admin-password":
        if len(rest) != 2:
            print("Использование: python3 manage.py set-admin-password <username> <password>")
            sys.exit(1)
        cmd_set_admin_password(rest[0], rest[1])
    elif command == "list-admins":
        cmd_list_admins()
    elif command == "restart-interface":
        cmd_restart_interface()
    else:
        print(f"Неизвестная команда: {command}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
