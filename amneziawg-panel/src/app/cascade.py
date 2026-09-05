"""
Каскад: маршрутизация исходящего TCP-трафика клиентов AmneziaWG через
внешний VLESS+Reality эндпоинт — второй хоп поверх обычного AWG-туннеля
(та же идея, что "каскадирование" в Amnezia/kaskad-pro: сервер сам прячется
за ещё одним прокси, вместо того чтобы светить собственным IP наружу).

Схема:
    клиент AWG --(awg0, PostUp REDIRECT)--> локальный xray (dokodemo-door)
                                                 --(vless outbound)--> VLESS-сервер --> интернет

xray-core запускается как обычный дочерний процесс панели (как в
vless-reality-docker), конфиг генерируется из ссылки vless://, вставленной
администратором в настройках сервера.

Важное ограничение: перехват через iptables REDIRECT (nat/PREROUTING)
работает только для TCP — у него нет аналога для UDP без TPROXY/fwmark.
Поэтому UDP/QUIC-трафик клиентов каскад не затрагивает и продолжает идти
напрямую через обычный MASQUERADE (см. awg_config.server_interface_block).
Для большинства сценариев (веб, мессенджеры без принудительного QUIC) это
не проблема: TCP fallback есть почти everywhere.
"""
from __future__ import annotations

import json
import shutil
import time
import subprocess
import threading
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .config import DATA_DIR

XRAY_BIN = shutil.which("xray") or "/usr/local/bin/xray"
CONFIG_PATH = DATA_DIR / "cascade-xray-config.json"

# Порт, на который iptables REDIRECT заворачивает TCP-трафик клиентов —
# должен совпадать с тем, что зашивается в PostUp/PostDown (awg_config.py).
REDIRECT_PORT = 12345
STATS_API_ADDR = "127.0.0.1:10086"

# Локальный socks-вход, через который панель сама ходит наружу, чтобы
# проверить каскад по-настоящему. Без него "здоровье" каскада измеряется
# фактом живости процесса — а именно этот показатель месяц врал, показывая
# running=true при нулевых счётчиках.
PROBE_PORT = 10087
PROBE_URL = "https://www.gstatic.com/generate_204"
PROBE_TIMEOUT_SECONDS = 12

# Логи xray: раньше уходили в DEVNULL, и при поломке смотреть было нечего.
LOG_PATH = DATA_DIR / "cascade-xray.log"
LOG_MAX_BYTES = 5 * 1024 * 1024

# Как часто супервизор проверяет каскад и как долго ждёт после неудач.
SUPERVISE_INTERVAL_SECONDS = 30
VERIFY_EVERY_SECONDS = 300
BACKOFF_START_SECONDS = 5
BACKOFF_MAX_SECONDS = 300

_health: dict = {
    "verified_ok": None,      # None — ещё не проверяли
    "verified_at": None,
    "verify_error": None,
    "restarts": 0,
    "last_restart_at": None,
}

_lock = threading.Lock()
_proc: subprocess.Popen | None = None
_last_url: str | None = None


class VlessParseError(ValueError):
    pass


def parse_vless_url(url: str) -> dict:
    """Разбирает vless://uuid@host:port?params#label. Поддерживается только
    security=reality (то, что генерирует наш же vless-reality-docker и
    большинство современных VLESS-панелей)."""
    url = (url or "").strip()
    if not url.startswith("vless://"):
        raise VlessParseError("Ссылка должна начинаться с vless://")
    parsed = urlparse(url)
    uuid = parsed.username
    host = parsed.hostname
    port = parsed.port
    if not uuid or not host or not port:
        raise VlessParseError("Не удалось разобрать uuid/адрес/порт из ссылки")
    q = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    security = q.get("security", "")
    if security != "reality":
        raise VlessParseError("Поддерживается только security=reality (то, что даёт наш VLESS-эндпоинт)")
    pbk = q.get("pbk")
    sni = q.get("sni")
    if not pbk or not sni:
        raise VlessParseError("В ссылке отсутствуют обязательные параметры pbk/sni")
    return {
        "uuid": uuid,
        "host": host,
        "port": port,
        "flow": q.get("flow", "xtls-rprx-vision"),
        "sni": sni,
        "pbk": pbk,
        "sid": q.get("sid", ""),
        "fp": q.get("fp") or "chrome",
        "label": unquote(parsed.fragment) if parsed.fragment else "",
    }


def build_xray_config(params: dict) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "stats": {},
        "api": {"tag": "api", "services": ["StatsService"]},
        "policy": {
            "system": {"statsOutboundUplink": True, "statsOutboundDownlink": True},
        },
        "inbounds": [
            {
                "tag": "api-in",
                "listen": "127.0.0.1",
                "port": 10086,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
            },
            {
                # Через этот вход панель сама делает пробный запрос наружу и
                # так отличает "каскад работает" от "процесс запустился".
                # Только loopback: наружу его отдавать нельзя.
                "tag": "probe-in",
                "listen": "127.0.0.1",
                "port": PROBE_PORT,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            },
            {
                "tag": "cascade-in",
                # iptables REDIRECT (nat/PREROUTING) для пакетов, реально пришедших
                # с awg0, переписывает destination на адрес входящего интерфейса
                # (awg0-сторона, например 10.13.13.1), а НЕ на 127.0.0.1 — тот
                # маппинг действует только для locally-generated пакетов. Слушать
                # нужно на всех интерфейсах, иначе редиректнутые клиентские
                # соединения получают TCP RST ещё до того, как долетают до xray.
                "listen": "0.0.0.0",
                "port": REDIRECT_PORT,
                "protocol": "dokodemo-door",
                # network включает udp: в режиме tproxy сюда приходят и QUIC,
                # и DNS — то, что при старом REDIRECT уходило мимо каскада
                # напрямую с реальным IP сервера.
                "settings": {"network": "tcp,udp", "followRedirect": True},
                # sockopt.tproxy обязателен, чтобы xray принял прозрачно
                # перенаправленные пакеты и увидел исходный адрес назначения.
                "streamSettings": {"sockopt": {"tproxy": "tproxy"}},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
            },
        ],
        "outbounds": [
            {
                "tag": "cascade-out",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": params["host"],
                            "port": params["port"],
                            "users": [{"id": params["uuid"], "encryption": "none", "flow": params["flow"]}],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": params["sni"],
                        "fingerprint": params["fp"],
                        "publicKey": params["pbk"],
                        "shortId": params.get("sid", ""),
                        "spiderX": "",
                    },
                },
            },
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "rules": [
                {"type": "field", "inboundTag": ["api-in"], "outboundTag": "api"},
                {"type": "field", "inboundTag": ["cascade-in"], "outboundTag": "cascade-out"},
                # Проба обязана идти тем же путём, что и клиентский трафик,
                # иначе она проверяет не то.
                {"type": "field", "inboundTag": ["probe-in"], "outboundTag": "cascade-out"},
            ]
        },
    }


def _stop_locked() -> None:
    global _proc, _last_url
    if _proc is not None and _proc.poll() is None:
        _proc.terminate()
        try:
            _proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _proc.kill()
    _proc = None
    _last_url = None


def is_running() -> bool:
    return _proc is not None and _proc.poll() is None


def sync(server) -> str | None:
    """Приводит фоновый процесс xray в соответствие с server.cascade_enabled /
    server.cascade_vless_url. Возвращает текст ошибки (или None, если всё ок
    либо каскад просто выключен). Вызывается из config_sync.apply_current_config,
    то есть при каждом сохранении/apply/restart настроек сервера — best effort,
    как и всё остальное управление в этой панели."""
    global _proc, _last_url
    with _lock:
        if not getattr(server, "cascade_enabled", False) or not (server.cascade_vless_url or "").strip():
            _stop_locked()
            return None

        if not (XRAY_BIN and Path(XRAY_BIN).exists()):
            _stop_locked()
            return "Бинарник xray не найден в образе — пересоберите контейнер (см. Dockerfile)"

        try:
            params = parse_vless_url(server.cascade_vless_url)
        except VlessParseError as exc:
            _stop_locked()
            return str(exc)

        # Если уже работаем с той же самой ссылкой — не дёргаем процесс зря
        # (иначе каждое сохранение любого поля сервера рвало бы уже
        # установленное каскадное соединение).
        if is_running() and _last_url == server.cascade_vless_url:
            return None

        _stop_locked()
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(build_xray_config(params), indent=2))
        CONFIG_PATH.chmod(0o600)
        try:
            _proc = subprocess.Popen(
                [XRAY_BIN, "run", "-config", str(CONFIG_PATH)],
                stdout=_open_log(),
                stderr=subprocess.STDOUT,
            )
        except OSError as exc:
            return f"Не удалось запустить xray: {exc}"
        _last_url = server.cascade_vless_url
        try:
            _proc.wait(timeout=0.4)
        except subprocess.TimeoutExpired:
            pass
        if not is_running():
            return "xray сразу завершился после запуска — проверьте ссылку vless:// (эндпоинт недоступен?)"
        return None


def _open_log():
    """Лог xray с примитивной ротацией: перед стартом обрезаем разросшийся
    файл. Полноценная ротация тут избыточна — файл нужен для разбора
    последней поломки, а не как журнал за всё время."""
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if LOG_PATH.exists() and LOG_PATH.stat().st_size > LOG_MAX_BYTES:
            LOG_PATH.unlink()
        return LOG_PATH.open("ab")
    except OSError:
        return subprocess.DEVNULL


def verify() -> tuple[bool, str | None]:
    """Проверка каскада реальным запросом наружу через него же.

    Именно эта проверка отличает работающий каскад от запустившегося
    процесса: при баге REALITY #6356 xray жив и счастлив, а трафик не идёт."""
    if not is_running():
        return False, "процесс xray не запущен"
    try:
        out = subprocess.run(
            ["curl", "--silent", "--output", "/dev/null", "--write-out", "%{http_code}",
             "--max-time", str(PROBE_TIMEOUT_SECONDS),
             "--proxy", f"socks5h://127.0.0.1:{PROBE_PORT}", PROBE_URL],
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_SECONDS + 5,
        )
    except Exception as exc:
        return False, f"проба не выполнилась: {exc}"
    code = (out.stdout or "").strip()
    if code == "204":
        return True, None
    if code in ("", "000"):
        return False, "через каскад не удалось установить соединение"
    return False, f"проба вернула HTTP {code} вместо 204"


def health() -> dict:
    """Состояние каскада для API: не только «жив ли процесс», но и
    «проходил ли через него трафик, когда мы последний раз смотрели»."""
    with _lock:
        return dict(_health)


def _record(ok: bool, error: str | None) -> None:
    from datetime import datetime, timezone
    with _lock:
        _health["verified_ok"] = ok
        _health["verified_at"] = datetime.now(timezone.utc).isoformat()
        _health["verify_error"] = error


def supervise(stop_event) -> None:
    """Фоновый надзор за каскадом.

    Решает две беды разом:
      1. Мёртвый xray при живом правиле перехвата = у всех клиентов молча
         пропадает весь TCP. Раньше это чинилось только руками через UI.
      2. «running: true» при нулевом трафике: процесс есть, каскада нет.

    Живость проверяется дёшево и часто, реальная проба — редко (она стоит
    сетевого запроса)."""
    from .database import SessionLocal
    from .models import ServerConfig

    backoff = BACKOFF_START_SECONDS
    last_verify = 0.0

    while not stop_event.wait(SUPERVISE_INTERVAL_SECONDS):
        db = SessionLocal()
        try:
            server = db.query(ServerConfig).first()
            if server is None:
                continue
            wanted = bool(server.cascade_enabled) and bool((server.cascade_vless_url or "").strip())
            if not wanted:
                continue

            if not is_running():
                from datetime import datetime, timezone
                error = sync(server)
                with _lock:
                    _health["restarts"] += 1
                    _health["last_restart_at"] = datetime.now(timezone.utc).isoformat()
                if error or not is_running():
                    _record(False, error or "не удалось поднять xray")
                    stop_event.wait(backoff)
                    backoff = min(backoff * 2, BACKOFF_MAX_SECONDS)
                    continue
                backoff = BACKOFF_START_SECONDS
                last_verify = 0.0  # после перезапуска проверяем сразу

            now = time.monotonic()
            if now - last_verify >= VERIFY_EVERY_SECONDS:
                ok, error = verify()
                _record(ok, error)
                last_verify = now
        except Exception:
            # Надзиратель не имеет права падать: он последняя линия обороны.
            pass
        finally:
            db.close()


def traffic_stats() -> dict | None:
    """Суммарный трафик через cascade-out (uplink/downlink в байтах,
    накопительно с момента старта xray) — по нему видно "идёт трафик или нет"."""
    if not is_running() or not (XRAY_BIN and Path(XRAY_BIN).exists()):
        return None
    try:
        out = subprocess.run(
            [XRAY_BIN, "api", "statsquery", f"-server={STATS_API_ADDR}", "-pattern", "outbound>>>cascade-out"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out.returncode != 0 or not out.stdout.strip():
            return None
        data = json.loads(out.stdout)
    except Exception:
        return None
    up = down = 0
    for item in data.get("stat", []) or []:
        name = item.get("name", "")
        val = int(item.get("value", 0) or 0)
        if name.endswith("uplink"):
            up += val
        elif name.endswith("downlink"):
            down += val
    return {"uplink": up, "downlink": down}
