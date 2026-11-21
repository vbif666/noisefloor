"""
Канарейка: панельная сторона.

cascade.verify() ходит через loopback и минует awg0, iptables, TPROXY и MTU.
Канарейка - отдельный контейнер со своим сетевым пространством, настоящий
AWG-клиент: панель заводит для него служебного пира и кладёт настройки в общий
каталог, а контейнер пишет туда результат проб (см. canary_probe.py).

Каталог общий только с контейнером канарейки. Сначала контейнер заявляет о себе
файлом результата, и только после этого панель заводит пира: на установке без
контейнера ничего не меняется.
"""
import json
import socket
import time
from datetime import datetime, timezone

from . import cascade, config_sync, crypto
from .config import DATA_DIR, settings
from .fsutil import atomic_write
from .ip_pool import next_available_ip
from .models import Peer, ServerConfig

CANARY_DIR = DATA_DIR / "canary"
CONFIG_PATH = CANARY_DIR / "config.json"
RESULT_PATH = CANARY_DIR / "result.json"

SERVICE_PEER_NAME = "canary"
SYNC_INTERVAL_SECONDS = 30
# Проба идёт раз в минуту, дольше трёх минут тишины значит, что контейнер мёртв.
STALE_AFTER_SECONDS = 180


# Подсказки для администратора, который не обязан разбираться в сетях: что
# сломалось простыми словами и что проверить самому, по шагам. Команды даны для
# каталога установки по умолчанию.
_RESTART_CANARY = ("cd /opt/noisefloor-panel && docker compose up -d canary")
_CANARY_LOGS = "docker logs --tail 50 NOISEFLOOR-canary"

HINTS: dict[str, dict] = {
    "stale": {
        "title": "Перестал отвечать сам модуль проверки",
        "meaning": "Канарейка — это служебная программа, которая раз в минуту "
                   "подключается к VPN как обычный клиент. Сейчас она молчит больше "
                   "трёх минут. Скорее всего, сломалась сама проверка, а не VPN: "
                   "клиенты при этом могут работать нормально.",
        "steps": [
            "Включите VPN на телефоне и откройте любой сайт. Если открывается — "
            "клиенты не пострадали, можно спокойно делать следующие шаги.",
            f"Перезапустите модуль проверки: зайдите на сервер по SSH и выполните "
            f"{_RESTART_CANARY}. Через 1–2 минуты строка в панели обновится.",
            f"Не помогло — выполните {_CANARY_LOGS} и отправьте вывод тому, кто "
            f"настраивал сервер.",
        ],
    },
    "handshake": {
        "title": "VPN-сервер не принимает подключения",
        "meaning": "Проверочный клиент не смог подключиться к этому серверу. "
                   "Скорее всего, у ваших пользователей VPN сейчас тоже не подключается.",
        "steps": [
            "Нажмите «Перезапустить туннель» вверху вкладки «Сервер» и подождите "
            "1–2 минуты.",
            "Не помогло — перезагрузите сервер из панели управления хостинга "
            "(кнопка «Перезагрузить»). Панель и VPN поднимутся сами.",
            "Если и после перезагрузки ошибка осталась — проверьте в панели хостинга, "
            "не закончилось ли место на диске и оплачен ли сервер.",
        ],
    },
    "dns": {
        "title": "Не находятся адреса сайтов",
        "meaning": "Подключение к VPN есть, но служба, которая превращает названия "
                   "сайтов (например, google.com) в адреса, не отвечает. У пользователей "
                   "VPN «подключён», а сайты не открываются.",
        "steps": [
            "На вкладке «Сервер» посмотрите поле «DNS для клиентов». Если там "
            "что-то необычное — впишите 1.1.1.1, 1.0.0.1 и сохраните.",
            "Если там уже стандартные адреса — значит, через релей не проходит "
            "интернет вообще. Нажмите «Проверить подключение» в блоке «Каскад» и "
            "посмотрите, что напишет панель.",
        ],
    },
    "exit_ip_mismatch": {
        "title": "Трафик идёт не через релей",
        "meaning": "Интернет через VPN работает, но сайты видят адрес этого сервера, "
                   "а не релея. Из-за этого заблокированные сайты и звонки "
                   "Telegram/WhatsApp могут не работать. Бывает и ложная тревога: "
                   "если сервер-релей выходит в интернет с другого адреса, чем тот, "
                   "по которому к нему подключаются.",
        "steps": [
            "Нажмите «Проверить подключение» в блоке «Каскад».",
            "Нажмите «Перезапустить туннель» вверху вкладки «Сервер» и подождите "
            "1–2 минуты.",
            "Сравните адрес «трафик выходит с …» из текста ошибки с адресом сервера-"
            "релея в панели его хостинга. Если это адрес релея — тревога ложная: "
            "впишите этот адрес в файл /opt/noisefloor-panel/.env строкой "
            "CANARY_EXPECTED_EXIT_IP=адрес и выполните "
            "cd /opt/noisefloor-panel && docker compose up -d.",
        ],
    },
    "exit_ip": {
        "title": "Через релей не проходит интернет",
        "meaning": "Клиенты подключаются к этому серверу, но дальше, через сервер-релей, "
                   "интернет не идёт. У пользователей VPN «подключён», а ничего не "
                   "открывается.",
        "steps": [
            "Нажмите «Проверить подключение» в блоке «Каскад». Если панель пишет "
            "«Релей не ответил» или «Трафик через релей не проходит» — проблема на "
            "сервере-релее.",
            "Зайдите в панель хостинга сервера-релея: он включён и оплачен? "
            "Перезагрузите его оттуда и подождите 3–5 минут.",
            "Если релеев несколько, панель сама переключится на рабочий в течение "
            "нескольких минут. Если релей один и он не оживает — на время выберите "
            "в блоке «Каскад» в поле «Если все релеи недоступны» вариант «Выпускать "
            "с адреса этого сервера», чтобы у пользователей хотя бы работал интернет.",
        ],
    },
    "download_slow": {
        "title": "Интернет через VPN очень медленный",
        "meaning": "Сайты открываются, но скорость слишком низкая: видео и загрузка "
                   "файлов у пользователей будут тормозить. Один такой замер — не "
                   "повод волноваться, проверка повторяется каждую минуту.",
        "steps": [
            "Подождите 10 минут. Если ошибка пропала — это была кратковременная "
            "перегрузка.",
            "Если держится — перезагрузите сервер-релей из панели его хостинга: "
            "часто тормозит именно он.",
            "Если медленно постоянно — возможно, хостинг ограничил скорость или "
            "трафик релея закончился. Проверьте тариф в панели хостинга.",
        ],
    },
    "download": {
        "title": "Мелкие запросы проходят, крупные обрываются",
        "meaning": "Сайты начинают открываться, но картинки, видео и файлы не "
                   "догружаются. Обычно это значит, что по пути режутся большие "
                   "пакеты данных, и помогает уменьшить их размер (MTU).",
        "steps": [
            "На вкладке «Сервер» в поле «MTU» впишите 1280 и сохраните.",
            "Подождите 2 минуты и посмотрите на эту строку. Если ошибка ушла — "
            "пользователям, у которых были проблемы, выдайте конфигурацию заново "
            "(новый QR-код или файл), в ней будет новый MTU.",
            "Не помогло — верните поле MTU пустым и перезагрузите сервер-релей "
            "из панели его хостинга.",
        ],
    },
    "download_http": {
        "title": "Проверочный сайт ответил ошибкой",
        "meaning": "Интернет через VPN есть, но сайт, с которого канарейка скачивает "
                   "проверочный файл, вернул ошибку. Чаще всего проблема у этого "
                   "сайта, а не у вас.",
        "steps": [
            "Включите VPN на телефоне и откройте пару сайтов. Если всё открывается — "
            "можно ничего не делать, ошибка уйдёт сама.",
            "Если держится больше часа и сайты у пользователей тоже не открываются — "
            "нажмите «Проверить подключение» в блоке «Каскад».",
        ],
    },
    "tunnel": {
        "title": "Модуль проверки не смог запуститься",
        "meaning": "Служебная программа проверки не смогла подготовить своё "
                   "подключение. Это поломка самой проверки: про работу VPN у "
                   "пользователей она ничего не говорит.",
        "steps": [
            "Включите VPN на телефоне и откройте любой сайт. Если открывается — "
            "клиенты не пострадали.",
            f"Перезапустите модуль проверки: на сервере по SSH выполните "
            f"{_RESTART_CANARY}.",
            f"Не помогло — выполните {_CANARY_LOGS} и отправьте вывод тому, кто "
            f"настраивал сервер.",
        ],
    },
}
HINTS["internal"] = HINTS["tunnel"]


def hint_for(stage: str | None, error: str | None) -> dict | None:
    """Подсказка по этапу, на котором упала проба. Внутри этапа уточняем по тексту."""
    if not stage:
        return None
    error = error or ""
    key = stage
    if stage == "exit_ip" and "выходит с" in error:
        key = "exit_ip_mismatch"
    elif stage == "download":
        if "HTTP" in error:
            key = "download_http"
        elif "скорость" in error or "заняло" in error:
            key = "download_slow"
    return HINTS.get(key)


def read_result() -> dict | None:
    try:
        data = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _age(result: dict) -> float:
    try:
        return time.time() - float(result.get("ts", 0))
    except (TypeError, ValueError):
        return float("inf")


def sidecar_present() -> bool:
    result = read_result()
    return result is not None and _age(result) < STALE_AFTER_SECONDS


def status() -> dict:
    """Состояние для API и метрик. ok=None - канарейка не настроена или ждёт."""
    empty = {"ok": None, "checked_at": None, "error": None, "stage": None,
             "hint": None, "exit_ip": None, "duration_ms": None, "speed_bps": None}
    result = read_result()
    if result is None or not CONFIG_PATH.exists():
        return empty
    checked_at = None
    try:
        checked_at = datetime.fromtimestamp(float(result["ts"]), tz=timezone.utc)
    except (KeyError, TypeError, ValueError):
        pass
    if _age(result) >= STALE_AFTER_SECONDS:
        return {**empty, "ok": False, "checked_at": checked_at, "stage": "stale",
                "error": "контейнер канарейки не присылает результатов",
                "hint": HINTS["stale"]}
    if result.get("state") != "probed":
        return empty
    ok = bool(result.get("ok"))
    return {
        "ok": ok,
        "checked_at": checked_at,
        "error": result.get("error"),
        "stage": result.get("stage"),
        "hint": None if ok else hint_for(result.get("stage"), result.get("error")),
        "exit_ip": result.get("exit_ip"),
        "duration_ms": result.get("duration_ms"),
        "speed_bps": result.get("speed_bps"),
    }


def service_peer(db) -> Peer | None:
    return db.query(Peer).filter(Peer.is_service.is_(True)).first()


def _create_service_peer(db, server: ServerConfig) -> Peer:
    priv, pub = crypto.generate_keypair()
    with config_sync.apply_lock:
        used = {a.split("/")[0] for (a,) in db.query(Peer.address).all()}
        used.add(server.address.split("/")[0])
        used.update(t.address.split("/")[0] for t in config_sync.get_tunnels(db))
        peer = Peer(
            name=SERVICE_PEER_NAME,
            private_key=priv,
            public_key=pub,
            preshared_key=crypto.generate_preshared_key(),
            address=next_available_ip(server.address, used),
            allowed_ips_client="0.0.0.0/0",
            persistent_keepalive=25,
            enabled=True,
            note="служебный пир канарейки",
            is_service=True,
        )
        db.add(peer)
        db.commit()
    db.refresh(peer)
    return peer


def expected_exit_ips(server: ServerConfig) -> list[str]:
    """С каких адресов должен выходить трафик: адреса релеев или явная настройка.

    Пустой список значит, что сверять не с чем, тогда адрес только показываем."""
    override = (settings.canary_expected_exit_ip or "").strip()
    if override:
        return [ip.strip() for ip in override.split(",") if ip.strip()]
    addresses: set[str] = set()
    for url in cascade.relay_urls(server):
        try:
            host = cascade.parse_vless_url(url)["host"]
            infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        except (cascade.VlessParseError, KeyError, OSError):
            # Адрес одного релея не разрешился. Сверять только с остальными
            # нельзя: выход через него выглядел бы утечкой.
            return []
        addresses.update(info[4][0] for info in infos)
    return sorted(addresses)


def build_config(peer: Peer, server: ServerConfig) -> dict:
    from .awg_config import client_config, effective_mtu
    return {
        "conf": client_config(peer, server),
        "address": peer.address,
        "mtu": effective_mtu(server),
        "dns": (server.dns or "").split(",")[0].strip(),
        "listen_port": server.listen_port,
        "expected_exit_ips": expected_exit_ips(server),
    }


def sync(db) -> None:
    """Привести служебного пира и файл настроек к текущему состоянию."""
    server = db.query(ServerConfig).first()
    if server is None:
        return
    wanted = (
        settings.canary_enabled
        and bool(server.cascade_enabled)
        and bool(cascade.relay_urls(server))
        and sidecar_present()
    )
    if not wanted:
        # Каскад выключен: контейнер снимает свой интерфейс и ждёт.
        try:
            CONFIG_PATH.unlink()
        except FileNotFoundError:
            pass
        return

    peer = service_peer(db)
    if peer is None:
        peer = _create_service_peer(db, server)
        config_sync.apply_current_config(db)

    content = json.dumps(build_config(peer, server), ensure_ascii=False, sort_keys=True)
    try:
        if CONFIG_PATH.read_text(encoding="utf-8") == content:
            return
    except OSError:
        pass
    atomic_write(CONFIG_PATH, content, mode=0o600)


def run(stop_event) -> None:
    from .database import SessionLocal

    while not stop_event.wait(SYNC_INTERVAL_SECONDS):
        db = SessionLocal()
        try:
            sync(db)
        except Exception as exc:
            print(f"[canary] {exc}")
        finally:
            db.close()
