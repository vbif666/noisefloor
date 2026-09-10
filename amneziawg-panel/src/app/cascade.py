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

Само по себе это не "мелкое неудобство": браузер предпочитает QUIC, и без
дополнительных мер основная часть трафика уходила бы мимо каскада, да ещё
и с настоящим адресом сервера — сайт видел бы два разных IP от одного
клиента. Поэтому в режиме redirect QUIC клиентам закрывают
(CASCADE_BLOCK_QUIC, отказ по icmp-port-unreachable — браузер сразу берёт
TCP), а DNS при желании заворачивают в каскад отдельным слушателем
(CASCADE_DNS_VIA_CASCADE). Правильное решение всё равно одно — ядро 6.x+
и режим tproxy.
"""
from __future__ import annotations

import json
import shutil
import time
import subprocess
import threading
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .config import DATA_DIR, settings

XRAY_BIN = shutil.which("xray") or "/usr/local/bin/xray"
CONFIG_PATH = DATA_DIR / "cascade-xray-config.json"

# Порт, на который iptables REDIRECT заворачивает TCP-трафик клиентов —
# должен совпадать с тем, что зашивается в PostUp/PostDown (awg_config.py).
REDIRECT_PORT = 12345
# Порт, куда nat REDIRECT заворачивает DNS клиентов в режиме redirect.
# Обычный UDP через REDIRECT не завернуть — исходный адрес назначения не
# восстановить, — но DNS этого и не требует: ответ важен, а кто ответил,
# клиенту всё равно. Так запрос уходит наружу по TCP через каскад и не
# светит настоящий адрес сервера. Включается CASCADE_DNS_VIA_CASCADE.
DNS_REDIRECT_PORT = 12353
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

# Строка, которой xray сообщает, что не смог сделать TCP-слушателя прозрачным.
# Она приходит уровнем Info и сама по себе процесс не роняет — а между тем без
# этого флага ядро дропает весь клиентский TCP (см. _tproxy_sockopt_error).
TPROXY_SOCKOPT_MARKER = "failed to set IP_TRANSPARENT"

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


def _tproxy_mode() -> bool:
    """Перехват идёт через TPROXY (а не через nat REDIRECT)?

    От этого зависит, как xray узнаёт исходный адрес назначения, и потому —
    какой у входа cascade-in должен быть streamSettings. Настройка одна и та
    же, что и у noisefloor-rules: CASCADE_INTERCEPT_MODE.
    """
    return getattr(settings, "cascade_intercept_mode", "tproxy") != "redirect"


def dns_via_cascade() -> bool:
    """Заворачивать ли DNS клиентов в каскад (только режим redirect).

    В tproxy-режиме DNS и так уходит через каскад вместе со всем UDP, и
    отдельный слушатель не нужен."""
    return bool(getattr(settings, "cascade_dns_via_cascade", False)) and not _tproxy_mode()


def build_xray_config(params: dict, dns_server: str = "1.1.1.1") -> dict:
    dns_inbounds = []
    dns_outbounds = []
    dns_rules = []
    if dns_via_cascade():
        dns_host, _, dns_port = (dns_server or "1.1.1.1").partition(":")
        dns_inbounds.append({
            "tag": "dns-in",
            "listen": "0.0.0.0",
            "port": DNS_REDIRECT_PORT,
            "protocol": "dokodemo-door",
            "settings": {"address": dns_host, "port": int(dns_port or 53), "network": "udp"},
        })
        dns_outbounds.append({
            "tag": "dns-out",
            "protocol": "dns",
            "settings": {"network": "tcp", "address": dns_host, "port": int(dns_port or 53)},
            # Запрос уходит не напрямую, а внутрь каскада — иначе смысл
            # перехвата теряется: адрес сервера видел бы уже DNS-резолвер.
            "proxySettings": {"tag": "cascade-out"},
        })
        dns_rules.append({"type": "field", "inboundTag": ["dns-in"], "outboundTag": "dns-out"})

    return {
        # access: none — иначе движок пишет строку на КАЖДОЕ соединение
        # клиента в тот же файл, куда идут ошибки. На проде это 23 МБ за
        # четыре дня и постоянная запись на диск ради данных, которые
        # никто не читает: панель разбирает только сообщения об ошибках.
        # Ротация (_rotate_log_if_needed) от роста спасала лишь на старте.
        "log": {"loglevel": "warning", "access": "none"},
        "stats": {},
        "api": {"tag": "api", "services": ["StatsService"]},
        "policy": {
            # Без этого блока действуют умолчания движка, а они для
            # прокси-режима вредны:
            #   connIdle 300 — соединение без трафика 5 минут закрывается.
            #     Так молча рвутся ssh, rdp, imap и вебсокеты мессенджеров;
            #     снаружи это выглядит как "иногда отваливается".
            #   uplinkOnly 2 / downlinkOnly 5 — после закрытия одной
            #     половины соединения вторую добивают через 2 и 5 секунд,
            #     чем обрезают хвост длинных ответов и больших загрузок.
            #     0 = ждать штатного закрытия.
            "levels": {"0": {
                "handshake": 8,
                "connIdle": 900,
                "uplinkOnly": 0,
                "downlinkOnly": 0,
            }},
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
                # напрямую с реальным IP сервера. В режиме redirect UDP до
                # xray не доходит вовсе, и объявлять его здесь незачем.
                "settings": {
                    "network": "tcp,udp" if _tproxy_mode() else "tcp",
                    "followRedirect": True,
                },
                # sockopt.tproxy нужен ТОЛЬКО для TPROXY: с ним xray берёт
                # исходный адрес назначения с прозрачного сокета. После nat
                # REDIRECT адрес на сокете — это сам xray, и каждое соединение
                # умирает с "loopback connection detected"; там адрес приходит
                # из SO_ORIGINAL_DST и никакого sockopt не требует.
                **(
                    {"streamSettings": {"sockopt": {"tproxy": "tproxy"}}}
                    if _tproxy_mode()
                    else {}
                ),
                # quic разбирают только там, где UDP вообще доходит до движка:
                # в redirect-режиме его в этом списке быть не должно.
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"] if _tproxy_mode() else ["http", "tls"],
                },
            },
            *dns_inbounds,
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
            *dns_outbounds,
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
                *dns_rules,
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
        dns_server = (getattr(server, "dns", "") or "1.1.1.1").split(",")[0].strip()
        CONFIG_PATH.write_text(json.dumps(build_xray_config(params, dns_server), indent=2))
        CONFIG_PATH.chmod(0o600)
        # Запоминаем, где кончается лог, чтобы потом читать только то, что
        # написал именно этот запуск, а не жалобы прошлого.
        log_offset = LOG_PATH.stat().st_size if LOG_PATH.exists() else 0
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
        return _tproxy_sockopt_error(log_offset)


def _tproxy_sockopt_error(log_offset: int) -> str | None:
    """Проверяет, получилось ли у xray сделать TCP-слушателя прозрачным.

    В режиме tproxy ядро отдаёт пакет локальному сокету только если на том
    стоит IP_TRANSPARENT. Если xray не смог его выставить (наблюдалось на
    ядре 5.15: UDP-слушатель флаг получает, TCP — нет, "operation not
    supported"), то xt_TPROXY просто дропает каждый клиентский TCP-пакет.
    Снаружи это выглядит идеально здоровым: процесс жив, проба через
    probe-in ходит (она идёт мимо перехвата), DNS по UDP работает — а у
    клиентов не открывается ни один сайт. Поэтому смотрим лог сами и
    показываем причину, вместо того чтобы молча отдать сломанный каскад."""
    if not _tproxy_mode():
        return None
    try:
        size = LOG_PATH.stat().st_size
        with LOG_PATH.open("rb") as fh:
            # Лог мог быть обрезан при старте — тогда читаем с начала.
            fh.seek(log_offset if size >= log_offset else 0)
            fresh = fh.read().decode("utf-8", "replace")
    except OSError:
        return None
    if TPROXY_SOCKOPT_MARKER not in fresh:
        return None
    return (
        "xray не смог включить IP_TRANSPARENT на TCP-слушателе — в режиме "
        "tproxy весь TCP клиентов будет отброшен ядром (UDP при этом "
        "работает). Так ведёт себя старое ядро: проверьте uname -r, "
        "обновите ядро до 6.x или переключите CASCADE_INTERCEPT_MODE=redirect."
    )


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


def _rotate_log_if_needed() -> None:
    """Обрезать лог, не трогая работающий процесс.

    Проверки на старте мало: каскад живёт неделями между перезапусками, и
    за это время файл успевал вырасти до десятков мегабайт на диске, где
    свободно три гигабайта. Обрезаем на месте — дескриптор открыт с
    O_APPEND, поэтому после truncate процесс продолжит писать с нуля, а не
    в дыру."""
    try:
        if LOG_PATH.exists() and LOG_PATH.stat().st_size > LOG_MAX_BYTES:
            with LOG_PATH.open("r+b") as fh:
                fh.truncate(0)
    except OSError:
        pass


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

            _rotate_log_if_needed()

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


# Счётчики спрашивает и график истории (раз в HISTORY_INTERVAL секунд), и
# каждый скрап /metrics. Каждый запрос — это запуск отдельного процесса
# `xray api`, поэтому одинаковые ответы отдаём из кэша: на одноядерной
# машине лишние запуски процессов заметны, а точность в пределах секунд
# графику не нужна.
STATS_CACHE_SECONDS = 4.0
_stats_cache: tuple[float, dict | None] = (0.0, None)


def traffic_stats() -> dict | None:
    """Суммарный трафик через cascade-out (uplink/downlink в байтах,
    накопительно с момента старта xray) — по нему видно "идёт трафик или нет"."""
    global _stats_cache
    if not is_running() or not (XRAY_BIN and Path(XRAY_BIN).exists()):
        return None
    cached_at, cached = _stats_cache
    if cached is not None and time.monotonic() - cached_at < STATS_CACHE_SECONDS:
        return cached
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
    stats = {"uplink": up, "downlink": down}
    _stats_cache = (time.monotonic(), stats)
    return stats
