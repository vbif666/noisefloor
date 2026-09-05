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
                "settings": {"network": "tcp", "followRedirect": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
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
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
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
