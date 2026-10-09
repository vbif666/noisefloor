from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base

from .config import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Столбцы, добавленные в ServerConfig ПОСЛЕ первого релиза. `Base.metadata.
# create_all()` создаёт только отсутствующие ТАБЛИЦЫ, а не добавляет новые
# столбцы к уже существующим (на серверах с persisted volume `data/` это
# приведёт к "no such column" при первом же запросе после обновления образа).
# Поэтому — простая ручная миграция: добавляем недостающее через ALTER TABLE.
_SERVER_CONFIG_MIGRATIONS = [
    ("cascade_enabled", "ALTER TABLE server_config ADD COLUMN cascade_enabled BOOLEAN NOT NULL DEFAULT 0"),
    ("cascade_vless_url", "ALTER TABLE server_config ADD COLUMN cascade_vless_url TEXT DEFAULT ''"),
    ("cascade_last_error", "ALTER TABLE server_config ADD COLUMN cascade_last_error TEXT"),
    ("cascade_sync_url", "ALTER TABLE server_config ADD COLUMN cascade_sync_url VARCHAR(255) DEFAULT ''"),
    ("cascade_sync_token", "ALTER TABLE server_config ADD COLUMN cascade_sync_token TEXT DEFAULT ''"),
    ("cascade_sync_error", "ALTER TABLE server_config ADD COLUMN cascade_sync_error TEXT"),
    ("cascade_synced_at", "ALTER TABLE server_config ADD COLUMN cascade_synced_at DATETIME"),
    ("split_ru_direct", "ALTER TABLE server_config ADD COLUMN split_ru_direct BOOLEAN NOT NULL DEFAULT 0"),
    ("cascade_relay_version", "ALTER TABLE server_config ADD COLUMN cascade_relay_version VARCHAR(64)"),
    ("cascade_sync_cert_pin", "ALTER TABLE server_config ADD COLUMN cascade_sync_cert_pin VARCHAR(400)"),
    ("header_protection_key", "ALTER TABLE server_config ADD COLUMN header_protection_key VARCHAR(64) DEFAULT ''"),
]


# То же для клиентов. Все, кто был до появления протоколов, подключены к
# основному интерфейсу AmneziaWG 2.0.
_PEER_MIGRATIONS = [
    ("protocol", "ALTER TABLE peers ADD COLUMN protocol VARCHAR(8) NOT NULL DEFAULT 'awg2'"),
]


# Туннели: S3/S4 появились вместе с отдельным интерфейсом AmneziaWG 2.0.
_TUNNEL_MIGRATIONS = [
    ("s3", "ALTER TABLE tunnels ADD COLUMN s3 INTEGER DEFAULT 0"),
    ("s4", "ALTER TABLE tunnels ADD COLUMN s4 INTEGER DEFAULT 0"),
]


def run_migrations() -> None:
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    for table, migrations in (
        ("server_config", _SERVER_CONFIG_MIGRATIONS),
        ("peers", _PEER_MIGRATIONS),
        ("tunnels", _TUNNEL_MIGRATIONS),
    ):
        if table not in tables:
            continue  # свежая БД — create_all() уже создал таблицу с полным набором столбцов
        existing = {col["name"] for col in inspector.get_columns(table)}
        with engine.begin() as conn:
            for column_name, ddl in migrations:
                if column_name not in existing:
                    conn.execute(text(ddl))
