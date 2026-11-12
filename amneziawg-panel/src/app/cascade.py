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
и режим tproxy. QUIC закрыт и там: через каскад он едет поверх TCP до
релея и тормозит страницы сильнее, чем TCP (см. noisefloor-rules).
"""
from __future__ import annotations

import json
import platform
import re
import shutil
import time
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .config import DATA_DIR, settings
from .fsutil import atomic_write

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
# Запросы не про адреса (TXT, HTTPS, MX) DNS-модуль не обрабатывает: исходящий
# dns-cache отдаёт их сюда, а отсюда они идут по обычному маршруту через каскад.
DNS_FORWARD_PORT = 12354
STATS_API_ADDR = "127.0.0.1:10086"

# База geoip лежит в каталоге ассетов движка (кладётся в образ, версия
# закреплена в Dockerfile). Без неё правило geoip:ru не с чем сверять, и
# разделение маршрутов включать нельзя — молча уехало бы всё в каскад.
GEOIP_PATH = Path("/usr/local/share/xray/geoip.dat")

# Локальный socks-вход, через который панель сама ходит наружу, чтобы
# проверить каскад по-настоящему. Без него "здоровье" каскада измеряется
# фактом живости процесса — а именно этот показатель месяц врал, показывая
# running=true при нулевых счётчиках.
PROBE_PORT = 10087
PROBE_TIMEOUT_SECONDS = 12

# Несколько релеев. Первый сохраняет тег cascade-out, остальные получают
# cascade-out-2, cascade-out-3: селектор балансировщика и запрос счётчиков в
# traffic_stats совпадают по префиксу и видят их все.
RELAY_TAG = "cascade-out"
BALANCER_TAG = "relays"
# Проба обязана проверять релеи: при «все недоступны - выпускать напрямую» она
# через обычный балансировщик вышла бы мимо них и показала здоровый каскад.
PROBE_BALANCER_TAG = "relays-probe"
ALL_DOWN_MODES = ("block", "direct")

# Как xray решает, какой релей жив. Мёртвый - у кого провалились все пробы за
# последние два цикла (цикл - OBSERVE_INTERVAL * OBSERVE_SAMPLING). Интервал
# короче 10 с xray молча поднимает до 10 с, поэтому sampling 1: при двух окно
# выросло бы до 40 с, а релей обязан смениться за 30. Одна потерянная проба
# релей не убивает: в окне их две.
# Запасной вход VLESS, см. fallback.py.
FALLBACK_TAG = "fallback-in"
# Вход открыт в интернет, и в отличие от клиента AWG его адрес никак не ограничен.
FALLBACK_BLOCKED_IPS = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "::1/128", "fc00::/7", "fe80::/10",
)
# Порты, которые слушает сам xray: совпадение с ними уронило бы его целиком.
RESERVED_TCP_PORTS = frozenset({10086, PROBE_PORT, REDIRECT_PORT, DNS_REDIRECT_PORT, DNS_FORWARD_PORT})

OBSERVE_INTERVAL = "10s"
OBSERVE_SAMPLING = 1
OBSERVE_TIMEOUT = "4s"

# Логи xray: раньше уходили в DEVNULL, и при поломке смотреть было нечего.
LOG_PATH = DATA_DIR / "cascade-xray.log"
LOG_MAX_BYTES = 5 * 1024 * 1024

# Строка, которой xray сообщает, что не смог сделать TCP-слушателя прозрачным.
# Она приходит уровнем Info и сама по себе процесс не роняет — а между тем без
# этого флага ядро дропает весь клиентский TCP (см. _tproxy_sockopt_error).
TPROXY_SOCKOPT_MARKER = "failed to set IP_TRANSPARENT"

# Как часто супервизор проверяет каскад.
SUPERVISE_INTERVAL_SECONDS = 30
VERIFY_EVERY_SECONDS = 300

# Перезапуск упавшего xray: паузы перед попытками, последняя - потолок. Счёт
# обнуляется, когда процесс прожил STABLE_SECONDS.
RESTART_DELAYS_SECONDS = (1, 2, 5, 10, 20, 40, 60)
STABLE_SECONDS = 60
WATCH_POLL_SECONDS = 1

_health: dict = {
    "verified_ok": None,      # None — ещё не проверяли
    "verified_at": None,
    "verify_error": None,
    "restarts": 0,
    "last_restart_at": None,
}

_lock = threading.Lock()
_proc: subprocess.Popen | None = None
# Конфиг, с которым запущен текущий процесс. Раньше здесь лежала только
# ссылка vless://, и от неё зависело решение «перезапускать или нет» — из-за
# чего смена любой ДРУГОЙ настройки (режим перехвата, разделение маршрутов,
# DNS) до движка не доезжала: ссылка та же, значит «ничего не изменилось».
_last_config: dict | None = None
# Должен ли xray работать. Отличает падение от штатной остановки в sync().
_wanted = False
_verify_soon = threading.Event()
# Тег исходящего -> адрес релея в запущенном конфиге.
_running_relays: dict[str, str] = {}
_fallback_warning: str | None = None


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
    try:
        port = parsed.port
    except ValueError as exc:
        # Например, IPv6 без квадратных скобок: urlparse не понимает, где
        # кончается адрес, и бросает ValueError — а наверху ждут только
        # VlessParseError, так что пользователь видел голую ошибку 500.
        raise VlessParseError("Не удалось разобрать порт из ссылки (IPv6-адрес пишется в [квадратных скобках])") from exc
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


def kernel_supports_tproxy(release: str | None = None) -> bool:
    """Тянет ли ядро TPROXY для TCP-слушателя xray.

    На ядрах младше 6.0 xray не может выставить IP_TRANSPARENT на
    TCP-слушателе, и xt_TPROXY молча дропает весь клиентский TCP. Контейнер
    работает на ядре хоста, так что platform.release() — это ядро сервера.
    Нераспознанную строку считаем новым ядром: сломанный tproxy панель
    заметит сама (_tproxy_sockopt_error), а молча терять UDP хуже.
    """
    release = release if release is not None else platform.release()
    try:
        return int(release.split(".", 1)[0]) >= 6
    except ValueError:
        return True


def intercept_mode() -> str:
    """Режим перехвата, которым панель реально пользуется: tproxy или redirect.

    CASCADE_INTERCEPT_MODE=auto (по умолчанию) выбирает по ядру: tproxy на
    6.x+, redirect на старых. Явные tproxy/redirect не переопределяются.
    Выбор по ядру, а не раз навсегда при установке, нужен, чтобы после
    обновления ядра и перезагрузки UDP (звонки Telegram/WhatsApp, QUIC, DNS)
    сам вернулся в каскад, без правки .env.
    """
    mode = (getattr(settings, "cascade_intercept_mode", "auto") or "auto").strip().lower()
    if mode in ("tproxy", "redirect"):
        return mode
    return "tproxy" if kernel_supports_tproxy() else "redirect"


def _tproxy_mode() -> bool:
    """Перехват идёт через TPROXY (а не через nat REDIRECT)?

    От этого зависит, как xray узнаёт исходный адрес назначения, и потому —
    какой у входа cascade-in должен быть streamSettings. Режим один и тот
    же, что передаётся noisefloor-rules: intercept_mode().
    """
    return intercept_mode() == "tproxy"


def dns_via_cascade() -> bool:
    """Заворачивать ли DNS клиентов в каскад (только режим redirect).

    В tproxy-режиме DNS и так уходит через каскад вместе со всем UDP, и
    отдельный слушатель не нужен."""
    return bool(getattr(settings, "cascade_dns_via_cascade", False)) and not _tproxy_mode()


def xudp_enabled() -> bool:
    return bool(getattr(settings, "cascade_xudp", False))


def dns_cache_enabled() -> bool:
    """Кэш имеет смысл там, где DNS клиентов вообще доходит до xray."""
    return xudp_enabled() and (_tproxy_mode() or dns_via_cascade())


def geoip_available() -> bool:
    return GEOIP_PATH.exists()


def relay_urls(server) -> list[str]:
    """Ссылки релеев по порядку, основной первым. Записи без ссылки пропускаем:
    релей с синхронизацией получает её при первом опросе."""
    rows = getattr(server, "relays", None) or []
    urls = [r.vless_url for r in rows] if rows else [getattr(server, "cascade_vless_url", "")]
    return [url.strip() for url in urls if (url or "").strip()]


def all_down_mode(server) -> str:
    mode = getattr(server, "cascade_all_down", "block")
    return mode if mode in ALL_DOWN_MODES else "block"


def probe_url() -> str:
    return getattr(settings, "cascade_probe_url", "") or "https://www.gstatic.com/generate_204"


def _relay_tag(index: int) -> str:
    return RELAY_TAG if index == 0 else f"{RELAY_TAG}-{index + 1}"


def _relay_outbound(tag: str, params: dict) -> dict:
    # concurrency -1: TCP без mux, иначе Vision не работает. UDP идёт через
    # XUDP, без него каждый новый порт источника стоил бы соединения TCP+REALITY.
    # UDP/443 это QUIC: браузер быстрее вернётся на TCP, чем дождётся его здесь.
    mux = {"enabled": True, "concurrency": -1, "xudpConcurrency": 16, "xudpProxyUDP443": "reject"}
    return {
        **({"mux": mux} if xudp_enabled() else {}),
        "tag": tag,
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
    }


def _balancing_block(all_down: str) -> dict:
    """Выбор живого релея.

    block тут не исходящий blackhole, а основной релей. До первых результатов
    проб (секунды после старта xray) leastPing живых не знает и отдаёт
    fallbackTag, и с blackhole каждый запуск обрывал бы клиентов. То же, если
    адрес проб сам недоступен: релеи исправны, а все выглядят мёртвыми. Если же
    релеи и правда лежат, соединение через основной просто не состоится, с
    адреса сервера никто не выйдет."""
    def balancer(tag: str, fallback: str) -> dict:
        return {
            "tag": tag,
            "selector": [RELAY_TAG],
            "strategy": {"type": "leastPing"},
            "fallbackTag": fallback,
        }

    return {
        "burstObservatory": {
            "subjectSelector": [RELAY_TAG],
            "pingConfig": {
                "destination": probe_url(),
                "interval": OBSERVE_INTERVAL,
                "sampling": OBSERVE_SAMPLING,
                "timeout": OBSERVE_TIMEOUT,
            },
        },
    }, [
        balancer(BALANCER_TAG, "direct" if all_down == "direct" else RELAY_TAG),
        balancer(PROBE_BALANCER_TAG, RELAY_TAG),
    ]


def _fallback_inbound(fallback: dict) -> dict:
    reality = {
        "dest": fallback["dest"],
        "serverNames": [fallback["sni"]],
        "privateKey": fallback["private_key"],
        "shortIds": [fallback["short_id"]],
    }
    if settings.vless_min_client_ver:
        # Без этого клиенты на sing-box получают отказ, см. config.py.
        reality["minClientVer"] = settings.vless_min_client_ver
    stream = {"network": "tcp", "security": "reality", "realitySettings": reality}
    behind_proxy = bool(settings.vless_behind_proxy)
    if behind_proxy:
        # Снаружи вход доступен только через nginx: напрямую без заголовка
        # PROXY соединение всё равно не прошло бы.
        stream["sockopt"] = {"acceptProxyProtocol": True}
    return {
        "tag": FALLBACK_TAG,
        "listen": "127.0.0.1" if behind_proxy else "0.0.0.0",
        "port": fallback["port"],
        "protocol": "vless",
        "settings": {
            "clients": [{"id": uuid, "flow": "xtls-rprx-vision"} for uuid in fallback["clients"]],
            "decryption": "none",
        },
        "streamSettings": stream,
    }


def _fallback_rules(relay_route: dict) -> list[dict]:
    """Только через релей: тот маршрут, что и у пробы, он никогда не выпускает
    напрямую. Разделения здесь нет: клиент VLESS присылает имена, а не адреса, и
    решать по ним на сервере было бы нечем. Имя, которое на релее разрешится в
    локальный адрес, этими правилами не поймать: кроме localhost их не знает никто."""
    tagged = {"type": "field", "inboundTag": [FALLBACK_TAG]}
    return [
        {"ruleTag": "nf-vless-private", **tagged, "ip": list(FALLBACK_BLOCKED_IPS), "outboundTag": "block"},
        {"ruleTag": "nf-vless-local", **tagged, "domain": ["full:localhost"], "outboundTag": "block"},
        {"ruleTag": "nf-vless", **tagged, **relay_route},
    ]


def _split_ru_rules(route: dict | None = None) -> list[dict]:
    """Правила разделения: российские адреса — напрямую, остальное — в каскад.

    Порядок здесь не косметика, а суть механизма. Выученные исключения
    (ruleTag nf-fallback, наполняется на следующем этапе) обязаны стоять
    ВЫШЕ правила geoip:ru: адрес числится российским, но не отвечает —
    значит идём в каскад, а не долбимся в него напрямую.

    Сам список исключений здесь пуст: его на ходу подменяет панель через
    `xray api adrules`, не перезапуская движок и не рвя соединения.
    """
    route = route or {"outboundTag": RELAY_TAG}
    return [
        {"ruleTag": "nf-private", "type": "field", "inboundTag": ["cascade-in"],
         "ip": ["geoip:private"], "outboundTag": "direct"},
        {"ruleTag": "nf-fallback", "type": "field", "inboundTag": ["cascade-in"],
         "ip": ["0.0.0.0/32"], **route},
        {"ruleTag": "nf-ru", "type": "field", "inboundTag": ["cascade-in"],
         "ip": ["geoip:ru"], "outboundTag": "direct"},
    ]


def build_xray_config(params: dict, dns_server: str = "1.1.1.1", split_ru_direct: bool = False,
                      reserves: list[dict] | tuple = (), all_down: str = "block",
                      fallback: dict | None = None) -> dict:
    # Один релей без выпуска напрямую выбирать не из чего: конфиг и трафик
    # остаются ровно такими, как до появления списка.
    balanced = bool(reserves) or all_down == "direct"
    observatory, balancers = _balancing_block(all_down) if balanced else ({}, [])
    route = {"balancerTag": BALANCER_TAG} if balanced else {"outboundTag": RELAY_TAG}
    probe_route = {"balancerTag": PROBE_BALANCER_TAG} if balanced else {"outboundTag": RELAY_TAG}

    dns_inbounds = []
    dns_outbounds = []
    dns_rules = []
    client_dns_rules = []
    dns_block = {}
    dns_host, _, dns_port = (dns_server or "1.1.1.1").partition(":")
    dns_port = int(dns_port or 53)
    if dns_via_cascade():
        dns_inbounds.append({
            "tag": "dns-in",
            "listen": "0.0.0.0",
            "port": DNS_REDIRECT_PORT,
            "protocol": "dokodemo-door",
            "settings": {"address": dns_host, "port": dns_port, "network": "udp"},
        })
    if dns_cache_enabled():
        # Запросы адресов отвечает DNS-модуль движка, в нём и живёт кэш. Его
        # собственные запросы приходят в маршрутизацию с тегом из dns.tag.
        dns_block = {"dns": {
            "tag": "dns-module",
            "servers": [{"address": dns_host, "port": dns_port}],
            "queryStrategy": "UseIP",
        }}
        dns_inbounds.append({
            "tag": "dns-forward",
            "listen": "127.0.0.1",
            "port": DNS_FORWARD_PORT,
            "protocol": "dokodemo-door",
            "settings": {"address": dns_host, "port": dns_port, "network": "udp"},
        })
        dns_outbounds.append({
            "tag": "dns-cache",
            "protocol": "dns",
            "settings": {"address": "127.0.0.1", "port": DNS_FORWARD_PORT, "network": "udp",
                         "nonIPQuery": "skip"},
        })
        client_dns_rules.append({"ruleTag": "nf-dns", "type": "field", "inboundTag": ["cascade-in"],
                                 "network": "udp", "port": 53, "outboundTag": "dns-cache"})
        if dns_via_cascade():
            dns_rules.append({"type": "field", "inboundTag": ["dns-in"], "outboundTag": "dns-cache"})
        dns_rules.append({"type": "field", "inboundTag": ["dns-module", "dns-forward"], **route})
    elif dns_via_cascade():
        if balanced:
            # proxySettings знает только конкретный исходящий, не балансировщик.
            # Поэтому при нескольких релеях запрос идёт обычным UDP через
            # выбранный релей: важно лишь, что адрес сервера резолвер не увидит.
            dns_rules.append({"type": "field", "inboundTag": ["dns-in"], **route})
        else:
            dns_outbounds.append({
                "tag": "dns-out",
                "protocol": "dns",
                "settings": {"network": "tcp", "address": dns_host, "port": dns_port},
                # Запрос уходит не напрямую, а внутрь каскада — иначе смысл
                # перехвата теряется: адрес сервера видел бы уже DNS-резолвер.
                "proxySettings": {"tag": RELAY_TAG},
            })
            dns_rules.append({"type": "field", "inboundTag": ["dns-in"], "outboundTag": "dns-out"})

    # Кэш идёт после nf-private: резолвер в локальной сети отвечает сам, и до
    # geoip:ru, иначе запрос к российскому резолверу ушёл бы мимо кэша.
    split_rules = _split_ru_rules(route) if split_ru_direct else []
    client_rules = [*split_rules[:1], *client_dns_rules, *split_rules[1:]]

    return {
        **dns_block,
        **observatory,
        # access: none — иначе движок пишет строку на КАЖДОЕ соединение
        # клиента в тот же файл, куда идут ошибки. На проде это 23 МБ за
        # четыре дня и постоянная запись на диск ради данных, которые
        # никто не читает: панель разбирает только сообщения об ошибках.
        # Ротация (_rotate_log_if_needed) от роста спасала лишь на старте.
        "log": {"loglevel": "warning", "access": "none"},
        "stats": {},
        # RoutingService нужен, чтобы менять набор правил на ходу
        # (`xray api adrules`): таблица исключений меняется часто, а
        # перезапуск движка рвёт все соединения клиентов разом.
        # HandlerService - замена исходящего при смене SNI, см. _swap_outbounds.
        "api": {"tag": "api", "services": ["StatsService", "RoutingService", "HandlerService"]},
        "policy": {
            # Без этого блока действуют умолчания движка, а они для
            # прокси-режима вредны:
            #   connIdle 300 — соединение без трафика 5 минут закрывается.
            #     Так молча рвутся ssh, rdp, imap и вебсокеты мессенджеров;
            #     снаружи это выглядит как "иногда отваливается".
            #   uplinkOnly / downlinkOnly — сколько держать вторую половину
            #     соединения после закрытия первой. Это таймеры БЕЗДЕЙСТВИЯ:
            #     пока данные идут, они продлеваются, хвост ответа не режут.
            #     Здесь щедрее умолчаний (2/5): путь двухшаговый, и остаток
            #     ответа сайта ещё должен дойти до клиента через второе плечо.
            #
            #     0 здесь ЗАПРЕЩЁН. В движке SetTimeout(0) — это finish()
            #     немедленно (common/signal/timer.go): как только сайт
            #     прислал FIN, соединение убивается целиком, недоставленный
            #     хвост ответа выбрасывается (Interrupt на pipe), клиенту
            #     улетает RST. С 2026-09-10 по 2026-09-14 здесь стоял 0 в
            #     уверенности, что это «ждать штатного закрытия», — в
            #     браузере это выглядело как частые ERR_SOCKET_NOT_CONNECTED
            #     (macOS отдаёт ENOTCONN на сброшенный сокет) и обрезанные
            #     ответы.
            "levels": {"0": {
                "handshake": 8,
                "connIdle": 900,
                "uplinkOnly": 5,
                "downlinkOnly": 10,
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
                    # Разделение сравнивает geoip с адресом, который клиент
                    # получил от своего DNS, а имя нужно только для правил.
                    # Без routeOnly имя заменило бы адрес, и сравнивать было
                    # бы не с чем. Панель при этом ничего не резолвит, поэтому
                    # заглушка от DNS хоста на решение не влияет. Наш релей
                    # разбирает имя сам и резолвит его на своей стороне.
                    **({"routeOnly": True} if split_ru_direct else {}),
                },
            },
            *dns_inbounds,
            *([_fallback_inbound(fallback)] if fallback else []),
        ],
        "outbounds": [
            *(_relay_outbound(_relay_tag(i), p) for i, p in enumerate([params, *reserves])),
            *dns_outbounds,
            # UseIPv4: адрес для прямого соединения берётся у DNS движка
            # (то есть из его кэша), и берётся именно v4. Без этого имя
            # разрешалось второй раз, системным резолвером, и российский
            # сайт с записью AAAA уезжал в IPv6 — которого в туннеле нет.
            # Имя сюда приходит только без разделения маршрутов, при выпуске
            # напрямую с мёртвыми релеями: с routeOnly здесь адрес клиента.
            {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            # AsIs: имена не разрешаем. geoip сравнивается с адресом клиента,
            # см. routeOnly у входа cascade-in.
            **({"domainStrategy": "AsIs"} if split_ru_direct else {}),
            **({"balancers": balancers} if balanced else {}),
            "rules": [
                {"ruleTag": "nf-api", "type": "field", "inboundTag": ["api-in"], "outboundTag": "api"},
                *(_fallback_rules(probe_route) if fallback else []),
                *client_rules,
                {"ruleTag": "nf-default", "type": "field", "inboundTag": ["cascade-in"], **route},
                # Проба обязана идти тем же путём, что и клиентский трафик,
                # иначе она проверяет не то. Правил разделения она не
                # касается: её задача — проверить именно каскад.
                {"ruleTag": "nf-probe", "type": "field", "inboundTag": ["probe-in"], **probe_route},
                *dns_rules,
            ]
        },
    }


def _stop_locked() -> None:
    global _proc, _last_config
    if _proc is not None and _proc.poll() is None:
        _proc.terminate()
        try:
            _proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _proc.kill()
    _proc = None
    _last_config = None


def is_running() -> bool:
    return _proc is not None and _proc.poll() is None


def _fallback_port() -> int | None:
    """Порт запасного входа в запущенном конфиге."""
    if not is_running() or not _last_config:
        return None
    return next((i["port"] for i in _last_config["inbounds"] if i["tag"] == FALLBACK_TAG), None)


def fallback_port() -> int | None:
    return _fallback_port()


def fallback_listening() -> bool:
    return _fallback_port() is not None


def fallback_warning() -> str | None:
    return _fallback_warning


def _resolve_fallback(server) -> dict | None:
    """Параметры входа, если его можно поднять. Занятый порт не должен стоить
    каскада всем остальным клиентам: без входа xray запустится."""
    global _fallback_warning
    from . import fallback

    _fallback_warning = None
    wanted = fallback.params(server)
    if wanted and wanted["port"] != _fallback_port() and not fallback.port_free(wanted["port"]):
        _fallback_warning = fallback.busy_message(wanted["port"])
        return None
    return wanted


def intercept_suspended(server) -> bool:
    """Снят ли перехват клиентов на то время, пока xray не работает.

    Только при «все недоступны - выпускать напрямую»: перехват без xray оставил
    бы клиентов без сети. При block так и задумано, и перехват остаётся, иначе
    клиенты вышли бы с адреса сервера.

    Считается на месте, а не хранится: то же значение нужно и правилам в PostUp,
    и сверке с ядром в надзоре."""
    return bool(server.cascade_enabled) and all_down_mode(server) == "direct" and not is_running()


def sync(server) -> str | None:
    """Приводит фоновый процесс xray в соответствие с server.cascade_enabled и
    списком релеев. Возвращает текст ошибки (или None, если всё ок
    либо каскад просто выключен). Вызывается из config_sync.apply_current_config,
    то есть при каждом сохранении/apply/restart настроек сервера — best effort,
    как и всё остальное управление в этой панели."""
    global _proc, _last_config, _wanted, _running_relays, _fallback_warning
    with _lock:
        _fallback_warning = None
        urls = relay_urls(server)
        if not getattr(server, "cascade_enabled", False) or not urls:
            _wanted = False
            _stop_locked()
            return None

        _wanted = True
        if not (XRAY_BIN and Path(XRAY_BIN).exists()):
            _stop_locked()
            return "Бинарник xray не найден в образе — пересоберите контейнер (см. Dockerfile)"

        # Испорченная ссылка резервного релея не повод оставлять клиентов без
        # основного: работаем с теми, что разобрались, и говорим об остальных.
        parsed: list[dict] = []
        bad: list[str] = []
        for url in urls:
            try:
                parsed.append(parse_vless_url(url))
            except VlessParseError as exc:
                bad.append(str(exc))
        if not parsed:
            # Без правки настроек повторять незачем.
            _wanted = False
            _stop_locked()
            return bad[0]
        partial_error = f"Часть релеев пропущена: {'; '.join(bad)}" if bad else None

        dns_server = (getattr(server, "dns", "") or "1.1.1.1").split(",")[0].strip()

        # Разделение включают в панели, но работать оно может только при
        # наличии базы geoip. Если базы нет — собираем обычный конфиг (весь
        # трафик в каскад, как раньше) и говорим об этом вслух: молча
        # проигнорировать включённую настройку хуже, чем не включить её.
        split = bool(getattr(server, "split_ru_direct", False))
        geoip_missing = split and not geoip_available()
        if geoip_missing:
            split = False

        wanted_fallback = _resolve_fallback(server)
        partial_error = partial_error or _fallback_warning
        config = build_xray_config(parsed[0], dns_server, split_ru_direct=split,
                                   reserves=parsed[1:], all_down=all_down_mode(server),
                                   fallback=wanted_fallback)
        relay_hosts = {_relay_tag(i): p["host"] for i, p in enumerate(parsed)}

        # Ничего не поменялось — не трогаем работающий процесс: перезапуск
        # рвёт все установленные соединения клиентов разом, а сохранение
        # настроек сервера случается по любому поводу.
        if is_running() and _last_config == config:
            return partial_error

        # Сменились только параметры релея, чаще всего SNI: ротация.
        changed = _changed_outbounds(_last_config, config) if is_running() else None
        if changed and _swap_outbounds(changed):
            atomic_write(CONFIG_PATH, json.dumps(config, indent=2), 0o600)
            _last_config = config
            _running_relays = relay_hosts
            return partial_error

        _stop_locked()
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(CONFIG_PATH, json.dumps(config, indent=2), 0o600)
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
        _last_config = config
        _running_relays = relay_hosts
        try:
            _proc.wait(timeout=0.4)
        except subprocess.TimeoutExpired:
            pass
        if not is_running():
            return "xray сразу завершился после запуска — проверьте ссылку vless:// (эндпоинт недоступен?)"
        if geoip_missing:
            return (
                f"Разделение маршрутов включено, но базы geoip нет ({GEOIP_PATH}) — "
                "весь трафик идёт через каскад. Обновите образ панели: база кладётся в него при сборке."
            )
        return _tproxy_sockopt_error(log_offset) or partial_error or _split_warning(split)


def _split_warning(split: bool) -> str | None:
    if split and not _tproxy_mode() and not dns_via_cascade():
        return (
            "Разделение маршрутов в режиме redirect без CASCADE_DNS_VIA_CASCADE: DNS клиентов идёт "
            "мимо каскада, и заблокированный домен с подменённым ответом может уйти напрямую."
        )
    return None


def _changed_outbounds(old: dict | None, new: dict) -> list[dict] | None:
    """Исходящие, которыми отличается новый конфиг. None: отличается чем-то ещё,
    на ходу это не применить."""
    if old is None:
        return None
    before = {o["tag"]: o for o in old["outbounds"]}
    after = {o["tag"]: o for o in new["outbounds"]}
    rest = lambda config: {k: v for k, v in config.items() if k != "outbounds"}
    if list(before) != list(after) or rest(old) != rest(new):
        return None
    return [o for tag, o in after.items() if before[tag] != o]


def _swap_outbounds(outbounds: list[dict]) -> bool:
    """Заменить исходящие в работающем xray. False: не вышло, нужен перезапуск.

    В плане стояли отдельные исходящие на каждый SNI и смена правила, но правила
    с балансировщиком выбирают не исходящий, а весь набор. Тег же остаётся
    прежним, и балансировщику с пробами менять нечего. Соединения, начатые через
    старый исходящий, живут до конца: rmo закрывает только сам обработчик.

    Новые соединения, пришедшиеся на миг между rmo и ado, закрываются: мимо релея
    они не уйдут, смок это проверяет. Если ado не прошёл, исходящего нет совсем, и
    отказ здесь ведёт к перезапуску."""
    swap_file = CONFIG_PATH.with_name("cascade-xray-swap.json")
    try:
        for outbound in outbounds:
            atomic_write(swap_file, json.dumps({"outbounds": [outbound]}), 0o600)
            for args in (["rmo", outbound["tag"]], ["ado", str(swap_file)]):
                out = subprocess.run([XRAY_BIN, "api", args[0], f"-server={STATS_API_ADDR}", args[1]],
                                     capture_output=True, text=True, timeout=5)
                if out.returncode != 0:
                    return False
        return True
    except (OSError, subprocess.SubprocessError):
        return False
    finally:
        swap_file.unlink(missing_ok=True)


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
             "--proxy", f"socks5h://127.0.0.1:{PROBE_PORT}", probe_url()],
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


def verify_now() -> tuple[bool, str | None]:
    """verify() с записью результата в health() — для проверки по кнопке."""
    ok, error = verify()
    _record(ok, error)
    return ok, error


def health() -> dict:
    """Состояние каскада для API: не только «жив ли процесс», но и
    «проходил ли через него трафик, когда мы последний раз смотрели»."""
    with _lock:
        return dict(_health)


def _record(ok: bool, error: str | None) -> None:
    with _lock:
        _health["verified_ok"] = ok
        _health["verified_at"] = datetime.now(timezone.utc).isoformat()
        _health["verify_error"] = error


def restart_delay(attempt: int) -> int:
    return RESTART_DELAYS_SECONDS[min(attempt, len(RESTART_DELAYS_SECONDS) - 1)]


def _note_down() -> None:
    """xray только что упал: снять перехват сразу, не дожидаясь перезапуска."""
    from . import config_sync
    from .database import SessionLocal

    db = SessionLocal()
    try:
        server = config_sync.get_server(db)
        if intercept_suspended(server):
            config_sync.ensure_rules(server, config_sync.interface_names(db, server))
    finally:
        db.close()


def _restart() -> bool:
    """Поднять xray и вернуть правила. False: поднимать не понадобилось.

    apply_lock берём здесь, а не в sync: при плановом перезапуске процесс тоже
    умирает, и сторож видит это раньше, чем sync успевает запустить новый. Под
    замком sync уже закончил, и остаётся проверить, что работа сделана."""
    from . import config_sync
    from .database import SessionLocal

    with config_sync.apply_lock:
        if is_running() or not _wanted:
            return False
        db = SessionLocal()
        try:
            server = config_sync.get_server(db)
            error = sync(server)
            with _lock:
                _health["restarts"] += 1
                _health["last_restart_at"] = datetime.now(timezone.utc).isoformat()
            if error or not is_running():
                _record(False, error or "не удалось поднять xray")
            server.cascade_last_error = error
            db.add(server)
            db.commit()
            config_sync.ensure_rules(server, config_sync.interface_names(db, server))
        finally:
            db.close()
    _verify_soon.set()
    return True


def watch(stop_event) -> None:
    """Сторож процесса xray.

    Мёртвый xray при живом правиле перехвата = у всех клиентов молча пропадает
    весь трафик. Раньше смерть замечалась раз в 30 секунд; здесь поток стоит на
    proc.wait() и узнаёт о ней сразу."""
    attempt = 0
    started_at = time.monotonic()
    while not stop_event.is_set():
        try:
            proc = _proc
            if proc is None and not _wanted:
                stop_event.wait(WATCH_POLL_SECONDS)
                continue
            if proc is not None:
                try:
                    proc.wait(timeout=WATCH_POLL_SECONDS)
                except subprocess.TimeoutExpired:
                    if time.monotonic() - started_at >= STABLE_SECONDS:
                        attempt = 0
                    continue
            if not _wanted:
                stop_event.wait(0.05)
                continue

            _note_down()
            if stop_event.wait(restart_delay(attempt)):
                return
            if _restart():
                attempt += 1
            started_at = time.monotonic()
        except Exception as exc:
            # Сторож не имеет права падать: он последняя линия обороны.
            print(f"[cascade] сторож xray: {exc}")
            stop_event.wait(WATCH_POLL_SECONDS)


def supervise(stop_event) -> None:
    """Фоновый надзор за каскадом: ловит «running: true» при нулевом трафике,
    когда процесс есть, а каскада нет. За самим процессом смотрит watch().

    Реальная проба стоит сетевого запроса, поэтому идёт редко."""
    from .database import SessionLocal
    from .models import ServerConfig

    global _wanted
    last_verify = 0.0

    while not stop_event.wait(SUPERVISE_INTERVAL_SECONDS):
        db = SessionLocal()
        try:
            server = db.query(ServerConfig).first()
            if server is None:
                continue
            wanted = bool(server.cascade_enabled) and bool(relay_urls(server))
            if not wanted:
                continue

            # Без автоприменения на старте sync ещё не вызывался: стороже нужно
            # знать, что xray должен работать.
            _wanted = True
            if not is_running():
                continue

            _rotate_log_if_needed()

            now = time.monotonic()
            if _verify_soon.is_set() or now - last_verify >= VERIFY_EVERY_SECONDS:
                _verify_soon.clear()
                ok, error = verify()
                _record(ok, error)
                last_verify = now
        except Exception:
            # Надзиратель не имеет права падать: он последняя линия обороны.
            pass
        finally:
            db.close()


def running_relay_count() -> int:
    return len(_running_relays)


def active_relay() -> str | None:
    """Адрес релея, который xray выбрал сейчас. None: живых нет, выбирать не из
    чего (один релей) или xray не ответил."""
    if len(_running_relays) < 2 or not is_running():
        return None
    try:
        out = subprocess.run(
            [XRAY_BIN, "api", "bi", f"-server={STATS_API_ADDR}", BALANCER_TAG],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return _running_relays.get(_selected_tag(out.stdout))


def _selected_tag(output: str) -> str | None:
    """Выбранный исходящий из вывода `xray api bi`. У команды нет JSON-режима,
    вывод текстовый:
      - Selects:
        1   cascade-out
    """
    match = re.search(r"Selects:\s*\n\s*\d+\s+(\S+)", output)
    return match.group(1) if match else None


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
