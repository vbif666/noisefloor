"""
VLESS+REALITY как самостоятельный протокол: свой xray, когда каскада нет.

Вход VLESS живёт в одном из двух процессов, и никогда в обоих сразу:

  * каскад включён - в xray каскада (cascade._fallback_inbound). Трафик идёт
    только через релей, тем же маршрутом, что проба, и напрямую не выходит;
  * каскад выключен - здесь, в отдельном xray с выходом прямо с этого сервера,
    как у клиентов AmneziaWG без каскада.

Отдельный процесс, а не тот же xray каскада в урезанном виде: от состояния
процесса каскада зависят перехват клиентов AWG, проба, уведомления и метрика
noisefloor_cascade_running. Запущенный ради VLESS xray выглядел бы там как
работающий каскад.

Порт один на оба режима, поэтому порядок в config_sync важен: при включении
каскада этот процесс останавливается до cascade.sync, а при выключении
поднимается после него, когда xray каскада порт уже отпустил.
"""
from __future__ import annotations

import json
import subprocess
import threading
import time
from pathlib import Path

from .config import DATA_DIR
from .fsutil import atomic_write

CONFIG_PATH = DATA_DIR / "vless-xray-config.json"
LOG_PATH = DATA_DIR / "vless-xray.log"
LOG_MAX_BYTES = 5 * 1024 * 1024
WATCH_POLL_SECONDS = 1
RESTART_DELAYS_SECONDS = (1, 2, 5, 10, 20, 40, 60)
STABLE_SECONDS = 60

_lock = threading.Lock()
_proc: subprocess.Popen | None = None
_last_config: dict | None = None
_wanted = False
_warning: str | None = None


def build_config(params: dict) -> dict:
    from .cascade import FALLBACK_BLOCKED_IPS, _fallback_inbound

    tagged = {"type": "field", "inboundTag": [_tag()]}
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [_fallback_inbound(params)],
        "outbounds": [
            # Первый исходящий - маршрут по умолчанию. UseIPv4: IPv6 на таких
            # серверах часто нет, а имя с записью AAAA уехало бы туда.
            {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            # IPOnDemand: клиент VLESS присылает имена, и без разрешения имени
            # правило по частным адресам не сработало бы. Имя, которое
            # разрешается в 127.0.0.1, открыло бы снаружи службы этого сервера,
            # которые слушают только loopback.
            "domainStrategy": "IPOnDemand",
            "rules": [
                {"ruleTag": "nf-vless-private", **tagged, "ip": list(FALLBACK_BLOCKED_IPS), "outboundTag": "block"},
                {"ruleTag": "nf-vless-local", **tagged, "domain": ["full:localhost"], "outboundTag": "block"},
                {"ruleTag": "nf-vless", **tagged, "outboundTag": "direct"},
            ],
        },
    }


def _tag() -> str:
    from .cascade import FALLBACK_TAG
    return FALLBACK_TAG


def cascade_wanted(server) -> bool:
    """Возьмёт ли вход на себя xray каскада. Та же проверка, что в начале
    cascade.sync: включён и есть хоть одна ссылка релея."""
    from . import cascade
    return bool(getattr(server, "cascade_enabled", False)) and bool(cascade.relay_urls(server))


def is_running() -> bool:
    return _proc is not None and _proc.poll() is None


def listening_port() -> int | None:
    if not is_running() or not _last_config:
        return None
    return _last_config["inbounds"][0]["port"]


def warning() -> str | None:
    return _warning


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


def stop() -> None:
    global _wanted
    with _lock:
        _wanted = False
        _stop_locked()


def sync(server) -> str | None:
    """Привести процесс в соответствие с настройками. Текст ошибки или None."""
    global _proc, _last_config, _wanted, _warning
    from . import cascade, fallback

    with _lock:
        _warning = None
        params = None if cascade_wanted(server) else fallback.params(server)
        if params is None:
            _wanted = False
            _stop_locked()
            return None

        _wanted = True
        if not (cascade.XRAY_BIN and Path(cascade.XRAY_BIN).exists()):
            _stop_locked()
            _warning = "Бинарник xray не найден в образе — пересоберите контейнер"
            return _warning

        config = build_config(params)
        if is_running() and _last_config == config:
            return None

        # Порт проверяем до остановки: свой же процесс его и держит.
        if params["port"] != listening_port() and not fallback.port_free(params["port"]):
            _wanted = False
            _stop_locked()
            _warning = fallback.busy_message(params["port"])
            return _warning

        _stop_locked()
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(CONFIG_PATH, json.dumps(config, indent=2), 0o600)
        _rotate_log_if_needed()
        try:
            with open(LOG_PATH, "ab") as log:
                _proc = subprocess.Popen(
                    [cascade.XRAY_BIN, "run", "-config", str(CONFIG_PATH)],
                    stdout=log, stderr=subprocess.STDOUT,
                )
        except OSError as exc:
            _warning = f"Не удалось запустить xray для VLESS: {exc}"
            return _warning
        _last_config = config
        try:
            _proc.wait(timeout=0.4)
        except subprocess.TimeoutExpired:
            pass
        if not is_running():
            _warning = f"xray для VLESS сразу завершился — см. {LOG_PATH.name}"
            return _warning
        return None


def _rotate_log_if_needed() -> None:
    try:
        if LOG_PATH.exists() and LOG_PATH.stat().st_size > LOG_MAX_BYTES:
            LOG_PATH.replace(LOG_PATH.with_suffix(".log.1"))
    except OSError:
        pass


def _restart() -> None:
    from . import config_sync
    from .database import SessionLocal

    with config_sync.apply_lock:
        if is_running() or not _wanted:
            return
        db = SessionLocal()
        try:
            error = sync(config_sync.get_server(db))
            if error:
                print(f"[vless] {error}")
        finally:
            db.close()


def watch(stop_event) -> None:
    """Сторож процесса: упавший xray поднимается с нарастающей паузой."""
    attempt = 0
    started_at = time.monotonic()
    while not stop_event.is_set():
        try:
            proc = _proc
            if not _wanted:
                stop_event.wait(WATCH_POLL_SECONDS)
                continue
            if proc is not None:
                try:
                    proc.wait(timeout=WATCH_POLL_SECONDS)
                except subprocess.TimeoutExpired:
                    if time.monotonic() - started_at >= STABLE_SECONDS:
                        attempt = 0
                    continue
                if not _wanted or proc is not _proc:
                    continue  # штатная остановка или уже перезапущен из sync
            print("[vless] xray не работает — перезапускаю")
            if stop_event.wait(RESTART_DELAYS_SECONDS[min(attempt, len(RESTART_DELAYS_SECONDS) - 1)]):
                return
            _restart()
            attempt += 1
            started_at = time.monotonic()
        except Exception as exc:
            print(f"[vless] сторож: {exc}")
            stop_event.wait(WATCH_POLL_SECONDS)
