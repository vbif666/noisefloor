"""
Список релеев каскада.

Настройки релея раньше лежали прямо в server_config. Теперь это таблица
cascade_relays, а релей из server_config становится её первой записью
(position 0, основной). Остальные записи - резервные.

Столбцы server_config остаются и повторяют основной релей. На них держатся
старый API (PUT /server с cascade_vless_url) и откат: прежняя версия панели
читает эти столбцы, про таблицу не знает и продолжает работать с основным
релеем.

Два направления копирования, и оба нужны:
  pull_primary - столбцы в запись. На старте (перенос и случай, когда старая
    версия успела поменять столбцы) и после PUT /server.
  push_primary - запись в столбцы. После синхронизации с релеем.
"""
from __future__ import annotations

from .models import CascadeRelay, ServerConfig

# Запись основного релея -> столбец server_config.
PRIMARY_FIELDS = (
    ("vless_url", "cascade_vless_url"),
    ("sync_url", "cascade_sync_url"),
    ("sync_token", "cascade_sync_token"),
    ("sync_error", "cascade_sync_error"),
    ("synced_at", "cascade_synced_at"),
    ("relay_version", "cascade_relay_version"),
    ("sync_cert_pin", "cascade_sync_cert_pin"),
)


def primary(server: ServerConfig) -> CascadeRelay | None:
    for relay in server.relays:
        if relay.position == 0:
            return relay
    return None


def pull_primary(db, server: ServerConfig) -> None:
    """Привести основную запись к столбцам server_config. Повторный вызов
    ничего не меняет."""
    relay = primary(server)
    configured = any(getattr(server, column, None) for _, column in PRIMARY_FIELDS)
    if relay is None:
        if not configured:
            return
        relay = CascadeRelay(position=0)
        server.relays.insert(0, relay)
    for field, column in PRIMARY_FIELDS:
        setattr(relay, field, getattr(server, column))
    db.add(relay)
    db.commit()
    db.refresh(server)


def push_primary(server: ServerConfig) -> None:
    relay = primary(server)
    if relay is None:
        return
    for field, column in PRIMARY_FIELDS:
        setattr(server, column, getattr(relay, field))


def add_reserve(db, server: ServerConfig, vless_url: str, sync_url: str, sync_token: str) -> CascadeRelay:
    # Резерв без основного не бывает: position 0 всегда занята, пусть и пустой
    # записью, иначе первый добавленный резерв стал бы основным.
    if primary(server) is None:
        server.relays.insert(0, CascadeRelay(position=0))
    relay = CascadeRelay(
        position=max(r.position for r in server.relays) + 1,
        vless_url=vless_url,
        sync_url=sync_url,
        sync_token=sync_token,
    )
    server.relays.append(relay)
    db.add(server)
    db.commit()
    db.refresh(relay)
    return relay
