"""
Синхронизация с релеем: панель сама забирает у него актуальные параметры.

Проблема, которую это решает. Параметры каскада заданы в двух местах: на
релее (его настройки) и на панели (ссылка vless://). Стоит поменять на релее
SNI или camouflage dest — и каскад молча перестаёт пропускать трафик, пока
кто-нибудь не обновит ссылку здесь вручную. Ровно так проект однажды провёл
несколько дней: обе стороны выглядели исправными, трафика не было.

Теперь достаточно указать адрес релея и его токен: панель периодически
спрашивает у релея, что у него сейчас, и подстраивается сама. Ссылка
vless:// становится производной величиной, а не второй копией настроек.

Токен отдельный от пароля администратора релея — панели-клиенту незачем
иметь над ним полную власть.
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from . import cascade

SYNC_INTERVAL_SECONDS = 300
REQUEST_TIMEOUT_SECONDS = 10
ALLOWED_SCHEMES = ("http", "https")


class SyncError(Exception):
    """Ошибка, которую имеет смысл показать администратору в панели."""


def _endpoint(base_url: str) -> str:
    base = (base_url or "").strip().rstrip("/")
    if not base:
        raise SyncError("Не указан адрес релея")
    if "://" not in base:
        # Частый случай: вписали "1.2.3.4:8001" без схемы.
        base = "http://" + base
    parsed = urllib.parse.urlparse(base)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SyncError(f"Поддерживаются только http и https, а не {parsed.scheme}")
    if not parsed.hostname:
        raise SyncError("В адресе релея не разобрать имя хоста")
    return base + "/api/sync"


def fetch_params(base_url: str, token: str) -> dict:
    """Спрашивает у релея его текущие параметры подключения."""
    if not (token or "").strip():
        raise SyncError("Не указан токен синхронизации")

    request = urllib.request.Request(
        _endpoint(base_url),
        headers={"Authorization": f"Bearer {token.strip()}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise SyncError("Релей не принял токен — проверьте, что скопирован целиком") from exc
        raise SyncError(f"Релей ответил {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise SyncError(f"Не удалось связаться с релеем: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise SyncError("Релей вернул не JSON — это точно адрес его панели?") from exc

    missing = [f for f in ("uuid", "port", "public_key", "sni") if not payload.get(f)]
    if missing:
        raise SyncError(f"В ответе релея нет полей: {', '.join(missing)}")
    return payload


def build_url(params: dict, fallback_host: str = "") -> str:
    """Собирает ссылку vless:// из ответа релея.

    Хост берём из ответа, но релей может не знать своего публичного адреса
    (PUBLIC_HOST не задан, определение через интернет не сработало). Тогда
    используем тот адрес, по которому мы до него только что достучались, —
    он заведомо рабочий."""
    host = (params.get("host") or "").strip()
    if not host or host == "YOUR-SERVER-IP":
        host = fallback_host
    if not host:
        raise SyncError("Релей не сообщил свой публичный адрес, и подставить нечего")

    query = {
        "type": "tcp",
        "security": "reality",
        "pbk": params["public_key"],
        "fp": params.get("fp") or "chrome",
        "sni": params["sni"],
        "sid": params.get("short_id", ""),
        "flow": params.get("flow") or "xtls-rprx-vision",
    }
    encoded = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in query.items())
    label = urllib.parse.quote(params.get("label") or "relay")
    return f"vless://{params['uuid']}@{host}:{params['port']}?{encoded}#{label}"


def host_of(base_url: str) -> str:
    base = (base_url or "").strip()
    if "://" not in base:
        base = "http://" + base
    return urllib.parse.urlparse(base).hostname or ""


def sync_once(db) -> tuple[bool, str | None]:
    """Один цикл синхронизации.

    Возвращает (изменилось ли, текст ошибки). Ошибку не бросаем: она должна
    доехать до панели и стать видимой, а не уронить фоновый поток."""
    from .config_sync import get_server

    server = get_server(db)
    if not server.cascade_enabled:
        return False, None
    if not (server.cascade_sync_url or "").strip():
        return False, None  # синхронизация не настроена — работаем по ручной ссылке

    try:
        params = fetch_params(server.cascade_sync_url, server.cascade_sync_token or "")
        new_url = build_url(params, fallback_host=host_of(server.cascade_sync_url))
    except SyncError as exc:
        server.cascade_sync_error = str(exc)
        db.add(server)
        db.commit()
        return False, str(exc)

    changed = new_url != (server.cascade_vless_url or "")
    server.cascade_sync_error = None
    server.cascade_synced_at = datetime.now(timezone.utc)
    if changed:
        server.cascade_vless_url = new_url
    db.add(server)
    db.commit()

    if changed:
        # Достаточно перезапустить каскадный xray: правила фаервола от
        # ссылки не зависят, поэтому туннель клиентов не трогаем.
        error = cascade.sync(server)
        if error:
            server.cascade_last_error = error
            db.add(server)
            db.commit()
            return True, error
    return changed, None


def run(stop_event: threading.Event) -> None:
    from .database import SessionLocal

    while not stop_event.wait(SYNC_INTERVAL_SECONDS):
        db = SessionLocal()
        try:
            sync_once(db)
        except Exception:
            # Фоновая синхронизация не имеет права ронять панель.
            pass
        finally:
            db.close()
