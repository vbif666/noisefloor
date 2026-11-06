"""
Самопроверка релея по трафику: живой процесс xray ещё не значит, что клиент
пройдёт. Временный xray-клиент подключается к своему же входу по REALITY, а
curl идёт через него наружу. Это та же проверка, что в tests/smoke.sh.

Результат входит в /api/health, поэтому хостовый агент откатывает и релиз,
который сломал REALITY. Отсюда три правила:

* Пока первого результата нет, здоровья нет: иначе контейнер станет healthy
  раньше проверки и сломанный релиз пройдёт.
* Один неудачный запуск не поломка: проба могла попасть в перезапуск xray при
  ротации. Поломка - FAIL_THRESHOLD неудач подряд.
* Если наружу не выходит и напрямую, проба ничего не доказывает: состояние
  unknown, здоровья это не отнимает. Релиз тут ни при чём.

SELFCHECK_INTERVAL_SECONDS=0 выключает проверку.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

log = logging.getLogger("selfcheck")

INTERVAL_SECONDS = int(os.environ.get("SELFCHECK_INTERVAL_SECONDS", "120"))
RETRY_SECONDS = int(os.environ.get("SELFCHECK_RETRY_SECONDS", "20"))
FAIL_THRESHOLD = 2
URL = os.environ.get("SELFCHECK_URL", "https://www.google.com/generate_204")
CURL_TIMEOUT_SECONDS = 12
DIRECT_TIMEOUT_SECONDS = 6
CLIENT_START_SECONDS = 5

_lock = threading.Lock()
_state: dict = {
    "state": "pending",  # pending | ok | failed | unknown | off
    "checked_at": None,
    "error": None,
    "failures": 0,
    "duration_ms": None,
}


class Failure(Exception):
    pass


def enabled() -> bool:
    return INTERVAL_SECONDS > 0


def snapshot() -> dict:
    with _lock:
        data = dict(_state)
    if not enabled():
        data["state"] = "off"
    return data


def healthy(data: dict | None = None) -> bool:
    data = data or snapshot()
    return data["state"] in ("ok", "unknown", "off")


def reset() -> None:
    with _lock:
        _state.update(state="pending", checked_at=None, error=None, failures=0, duration_ms=None)


def client_config(creds: dict, socks_port: int) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
                      "settings": {"udp": False}}],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": "127.0.0.1",
                "port": creds["vless_port"],
                "users": [{"id": creds["uuid"], "flow": "xtls-rprx-vision", "encryption": "none"}],
            }]},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": creds["sni"],
                    "fingerprint": "chrome",
                    "publicKey": creds["public_key"],
                    "shortId": creds["short_id"],
                },
            },
        }],
    }


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_port(port: int, proc: subprocess.Popen) -> None:
    deadline = time.monotonic() + CLIENT_START_SECONDS
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise Failure(f"xray-клиент завершился с кодом {proc.returncode}")
        with socket.socket() as sock:
            sock.settimeout(0.5)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise Failure("xray-клиент не открыл порт")


def _http_code(url: str, timeout: int, socks_port: int | None = None) -> int:
    """Код ответа, 0 - ответа не было."""
    cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", str(timeout)]
    if socks_port:
        cmd += ["-x", f"socks5h://127.0.0.1:{socks_port}"]
    try:
        out = subprocess.run(cmd + [url], capture_output=True, text=True, timeout=timeout + 3)
    except (subprocess.TimeoutExpired, OSError):
        return 0
    try:
        return int(out.stdout.strip() or 0)
    except ValueError:
        return 0


def through_reality(creds: dict, xray_bin: str) -> None:
    """Проход через свой вход. Бросает Failure, если клиент не прошёл."""
    port = _free_port()
    fd, path = tempfile.mkstemp(prefix="selfcheck-", suffix=".json")  # права 0600
    proc = None
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(client_config(creds, port), f)
        proc = subprocess.Popen([xray_bin, "run", "-c", path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _wait_port(port, proc)
        code = _http_code(URL, CURL_TIMEOUT_SECONDS, port)
        if not 200 <= code < 400:
            raise Failure(f"через REALITY нет ответа (HTTP {code})")
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        Path(path).unlink(missing_ok=True)


def run_once(load_creds: Callable[[], dict], xray_bin: str) -> dict:
    started = time.monotonic()
    error = None
    try:
        through_reality(load_creds(), xray_bin)
        outcome = "ok"
    except Failure as exc:
        error = str(exc)
        outcome = "failed" if _http_code(URL, DIRECT_TIMEOUT_SECONDS) else "unknown"
    except (OSError, KeyError, ValueError) as exc:
        error = f"{type(exc).__name__}: {exc}"
        outcome = "failed"
    return _record(outcome, error, int((time.monotonic() - started) * 1000))


def _record(outcome: str, error: str | None, duration_ms: int) -> dict:
    with _lock:
        previous = _state["state"]
        _state["checked_at"] = datetime.now(timezone.utc).isoformat()
        _state["duration_ms"] = duration_ms
        _state["error"] = error
        if outcome == "failed":
            _state["failures"] += 1
            if _state["failures"] >= FAIL_THRESHOLD:
                _state["state"] = "failed"
        else:
            _state["failures"] = 0
            _state["state"] = outcome
        current = _state["state"]
        data = dict(_state)
    if current != previous:
        log.warning("самопроверка: %s -> %s %s", previous, current, error or "")
    return data


def next_delay(data: dict) -> int:
    return RETRY_SECONDS if data["failures"] and data["state"] != "failed" else INTERVAL_SECONDS


def run(stop_event: threading.Event, load_creds: Callable[[], dict], xray_bin: str) -> None:
    if not enabled():
        return
    if stop_event.wait(2):  # даём xray открыть порт
        return
    while not stop_event.is_set():
        try:
            data = run_once(load_creds, xray_bin)
        except Exception:  # поток не должен умирать: без него здоровье застынет
            log.exception("самопроверка упала")
            data = snapshot()
        if stop_event.wait(next_delay(data)):
            return
