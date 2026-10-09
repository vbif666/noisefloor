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

Связь только по HTTPS. Сертификат у релея самоподписанный (у сервера по IP
другого обычно нет), поэтому цепочку не проверяем, а запоминаем отпечаток
сертификата при первом успешном обращении и дальше требуем ровно его
(TOFU, как ssh known_hosts). Отпечаток привязан к адресу: сменили адрес
релея в настройках — запоминается заново.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import socket
import ssl
import threading
import urllib.parse
from datetime import datetime, timezone

from . import cascade

SYNC_INTERVAL_SECONDS = 300
REQUEST_TIMEOUT_SECONDS = 10
ALLOWED_SCHEMES = ("http", "https")
SYNC_PATH = "/api/sync"
# Релей умеет менять SNI по расписанию и объявляет момент смены заранее.
# Приходим за новыми параметрами чуть позже объявленного времени — релею
# нужно несколько секунд, чтобы перезапустить свой xray. Если пришли, а он
# ещё не переключился, повторяем не реже чем раз в MIN_WAIT.
ROTATION_GRACE_SECONDS = 5
MIN_WAIT_SECONDS = 10

# Когда релей сменит SNI в следующий раз (по его последнему ответу). Только
# в памяти: после перезапуска панели узнаем заново на первом же опросе.
next_rotation_at: datetime | None = None


class SyncError(Exception):
    """Ошибка, которую имеет смысл показать администратору в панели."""


def _normalise(base_url: str) -> urllib.parse.ParseResult:
    base = (base_url or "").strip().rstrip("/")
    if not base:
        raise SyncError("Не указан адрес релея")
    if "://" not in base:
        # Частый случай: вписали "1.2.3.4:8001" без схемы.
        base = "https://" + base
    parsed = urllib.parse.urlparse(base)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SyncError(f"Поддерживается только https, а не {parsed.scheme}")
    if not parsed.hostname:
        raise SyncError("В адресе релея не разобрать имя хоста")
    # Релей отдаёт панель только по HTTPS; старый адрес с http:// из
    # прежних настроек молча поднимаем до https, а не ломаем каскад.
    return parsed._replace(scheme="https")


def _endpoint(base_url: str) -> str:
    return _normalise(base_url).geturl() + SYNC_PATH


KEY_PIN_PREFIX = "key:"


def cert_fingerprint(der: bytes) -> str:
    """Отпечаток всего сертификата - формат старых записей."""
    return hashlib.sha256(der).hexdigest()


def key_fingerprint(der: bytes) -> str:
    """Отпечаток публичного ключа сертификата.

    Релей перевыпускает сертификат перед истечением, но с тем же ключом, поэтому
    запоминаем ключ: плановый перевыпуск не ломает каскад, а подмена ключа -
    ловится."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError as exc:
        raise SyncError("Релей прислал нечитаемый сертификат") from exc
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return KEY_PIN_PREFIX + hashlib.sha256(spki).hexdigest()


def pin_matches(pinned: str, der: bytes) -> bool:
    if pinned.startswith(KEY_PIN_PREFIX):
        return key_fingerprint(der) == pinned
    # Запись старого формата (отпечаток сертификата): принимаем, после
    # успешной синхронизации она перезапишется отпечатком ключа.
    return cert_fingerprint(der) == pinned


def _pin_for(pin_record: str, base_url: str) -> str:
    """Запомненный отпечаток, если он записан для этого же адреса."""
    fp, _, url = (pin_record or "").partition("|")
    return fp if fp and url == _endpoint(base_url) else ""


def make_pin_record(fingerprint: str, base_url: str) -> str:
    return f"{fingerprint}|{_endpoint(base_url)}"


def _request(base_url: str, token: str, pinned: str) -> tuple[int, bytes, str]:
    parsed = _normalise(base_url)
    path = (parsed.path or "") + SYNC_PATH
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(
        parsed.hostname, parsed.port or 443,
        timeout=REQUEST_TIMEOUT_SECONDS, context=context,
    )
    try:
        conn.connect()
        der = conn.sock.getpeercert(binary_form=True) or b""
        fingerprint = key_fingerprint(der)
        # Отпечаток сверяем ДО отправки токена: иначе подменённый сервер
        # получил бы токен синхронизации.
        if pinned and not pin_matches(pinned, der):
            raise SyncError(
                "Ключ сертификата релея не совпадает с запомненным. Если вы "
                "сменили ключ на релее - сохраните адрес релея заново; "
                "если нет - возможна подмена, синхронизация остановлена"
            )
        conn.request("GET", path, headers={
            "Authorization": f"Bearer {token.strip()}",
            "Accept": "application/json",
            "Host": parsed.netloc,
        })
        response = conn.getresponse()
        return response.status, response.read(), fingerprint
    finally:
        conn.close()


def fetch_params(base_url: str, token: str, pin_record: str = "") -> tuple[dict, str]:
    """Спрашивает у релея его текущие параметры подключения.

    Возвращает (параметры, отпечаток сертификата релея)."""
    if not (token or "").strip():
        raise SyncError("Не указан токен синхронизации")
    pinned = _pin_for(pin_record, base_url)
    try:
        code, body, fingerprint = _request(base_url, token, pinned)
    except SyncError:
        raise
    except ssl.SSLError as exc:
        raise SyncError(
            f"Не удалось установить HTTPS с релеем ({exc.reason or exc}). "
            "Релей обновлён до версии с HTTPS?"
        ) from exc
    except (OSError, socket.timeout, http.client.HTTPException) as exc:
        raise SyncError(f"Не удалось связаться с релеем: {exc}") from exc

    if code == 401:
        raise SyncError("Релей не принял токен — проверьте, что скопирован целиком")
    if code != 200:
        raise SyncError(f"Релей ответил {code}")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SyncError("Релей вернул не JSON — это точно адрес его панели?") from exc
    if not isinstance(payload, dict):
        raise SyncError("Релей вернул не JSON-объект")

    missing = [f for f in ("uuid", "port", "public_key", "sni") if not payload.get(f)]
    if missing:
        raise SyncError(f"В ответе релея нет полей: {', '.join(missing)}")
    return payload, fingerprint


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
    # IPv6 в ссылке обязан стоять в скобках: без них "2a01::1:443" не
    # разобрать на адрес и порт, и страница каскада падала с ошибкой 500.
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"vless://{params['uuid']}@{host}:{params['port']}?{encoded}#{label}"


def parse_next_rotation(params: dict) -> datetime | None:
    """Момент следующей смены SNI из ответа релея; None, если ротация
    выключена или релей старый и про неё не знает."""
    rotation = params.get("rotation") or {}
    if not rotation.get("enabled") or not rotation.get("next_at"):
        return None
    try:
        at = datetime.fromisoformat(str(rotation["next_at"]))
    except ValueError:
        return None
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    return at


def wait_seconds(next_at: datetime | None, now: datetime | None = None) -> float:
    """Сколько спать до следующего опроса: обычный интервал, но не позже
    чем через несколько секунд после объявленной смены SNI."""
    if next_at is None:
        return SYNC_INTERVAL_SECONDS
    now = now or datetime.now(timezone.utc)
    until = (next_at - now).total_seconds() + ROTATION_GRACE_SECONDS
    return max(MIN_WAIT_SECONDS, min(SYNC_INTERVAL_SECONDS, until))


def host_of(base_url: str) -> str:
    base = (base_url or "").strip()
    if "://" not in base:
        base = "https://" + base
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

    global next_rotation_at
    try:
        params, fingerprint = fetch_params(
            server.cascade_sync_url, server.cascade_sync_token or "",
            server.cascade_sync_cert_pin or "",
        )
        new_url = build_url(params, fallback_host=host_of(server.cascade_sync_url))
    except SyncError as exc:
        server.cascade_sync_error = str(exc)
        db.add(server)
        db.commit()
        return False, str(exc)

    next_rotation_at = parse_next_rotation(params)
    changed = new_url != (server.cascade_vless_url or "")
    server.cascade_sync_error = None
    server.cascade_sync_cert_pin = make_pin_record(fingerprint, server.cascade_sync_url)
    server.cascade_synced_at = datetime.now(timezone.utc)
    relay_build = params.get("version") if isinstance(params, dict) else None
    if isinstance(relay_build, dict):
        server.cascade_relay_version = str(relay_build.get("version") or "")[:64] or None
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

    while not stop_event.wait(wait_seconds(next_rotation_at)):
        db = SessionLocal()
        try:
            sync_once(db)
        except Exception:
            # Фоновая синхронизация не имеет права ронять панель.
            pass
        finally:
            db.close()
