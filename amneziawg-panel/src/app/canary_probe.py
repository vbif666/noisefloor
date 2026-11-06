"""
Канарейка: контейнерная сторона, запускается как `python -m app.canary_probe`.

Настоящий AWG-клиент в своём сетевом пространстве. Раз в минуту проверяет через
туннель DNS, адрес выхода и скачивание примерно мегабайта. Пустой 204 не годится:
он не покажет PMTU black hole, где мелкие пакеты проходят, а данные встают.

Только стандартная библиотека: пакет app целиком тут не нужен, и импорт настроек
создал бы лишние файлы. Секретов контейнер не получает, кроме ключа своего пира.
"""
import hashlib
import json
import os
import random
import re
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path

IFACE = "canary0"
DEFAULT_MTU = 1380
RESOLV_CONF = Path("/etc/resolv.conf")
# Рукопожатие обновляется раз в две минуты, старше трёх - туннель не живёт.
HANDSHAKE_MAX_AGE_SECONDS = 180
HANDSHAKE_WAIT_SECONDS = 8


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, ""))
    except ValueError:
        return default


CANARY_DIR = Path(os.environ.get("CANARY_DIR", "/canary"))
INTERVAL_SECONDS = _env_int("CANARY_INTERVAL_SECONDS", 60)
TRACE_URL = os.environ.get("CANARY_TRACE_URL", "https://www.cloudflare.com/cdn-cgi/trace")
DOWNLOAD_URL = os.environ.get("CANARY_DOWNLOAD_URL", "https://speed.cloudflare.com/__down?bytes=1048576")
DOWNLOAD_BYTES = _env_int("CANARY_DOWNLOAD_BYTES", 1048576)
MAX_DOWNLOAD_SECONDS = _env_int("CANARY_MAX_DOWNLOAD_SECONDS", 20)
MIN_SPEED_BPS = _env_int("CANARY_MIN_SPEED_BPS", 64 * 1024)
DNS_NAMES = os.environ.get("CANARY_DNS_NAMES", "www.cloudflare.com,www.google.com").split(",")
DNS_SERVER = os.environ.get("CANARY_DNS_SERVER", "")
# Куда стучаться: по умолчанию шлюз bridge-сети, то есть сам хост с панелью.
ENDPOINT_HOST = os.environ.get("CANARY_ENDPOINT_HOST", "")


class ProbeError(Exception):
    def __init__(self, stage: str, message: str):
        super().__init__(message)
        self.stage = stage


# --- пробы ---------------------------------------------------------------

def build_dns_query(name: str, query_id: int) -> bytes:
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    labels = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.strip(".").split("."))
    return header + labels + b"\x00" + struct.pack("!HH", 1, 1)


def parse_dns_answer(data: bytes, query_id: int) -> tuple[int, int]:
    """(rcode, число ответов); ValueError, если это не ответ на наш запрос."""
    if len(data) < 12:
        raise ValueError("короткий ответ DNS")
    got_id, flags, _qd, answers, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if got_id != query_id or not flags & 0x8000:
        raise ValueError("чужой ответ DNS")
    return flags & 0x000F, answers


def check_dns(server: str, names: list[str], timeout: float = 3.0, port: int = 53) -> None:
    """Запрос руками, а не getaddrinfo: важно спросить через туннель именно server."""
    for name in names:
        name = name.strip()
        if not name:
            continue
        query_id = random.randint(1, 0xFFFF)
        answer = None
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            for _ in range(2):
                try:
                    sock.sendto(build_dns_query(name, query_id), (server, port))
                    answer = parse_dns_answer(sock.recv(1500), query_id)
                    break
                except (OSError, ValueError):
                    continue
        if answer is None:
            raise ProbeError("dns", f"{server} не ответил на запрос {name}")
        if answer[0] != 0 or answer[1] == 0:
            raise ProbeError("dns", f"{server} не разрешил {name} (rcode {answer[0]})")


def parse_trace_ip(text: str) -> str | None:
    match = re.search(r"^ip=(\S+)$", text, re.MULTILINE)
    return match.group(1) if match else None


def check_exit_ip(expected: list[str]) -> str:
    out = subprocess.run(
        ["curl", "--silent", "--show-error", "--max-time", "15", TRACE_URL],
        capture_output=True, text=True, timeout=20,
    )
    if out.returncode != 0:
        detail = (out.stderr or "").strip() or f"код {out.returncode}"
        raise ProbeError("exit_ip", f"адрес выхода не определён: {detail}")
    ip = parse_trace_ip(out.stdout)
    if ip is None:
        raise ProbeError("exit_ip", "в ответе нет адреса выхода")
    if expected and ip not in expected:
        raise ProbeError("exit_ip", f"трафик выходит с {ip}, а не с адреса релея ({', '.join(expected)})")
    return ip


def evaluate_download(code: str, size: int, seconds: float, *, expected_bytes: int,
                      max_seconds: float, min_bps: float) -> tuple[float | None, str | None]:
    """(скорость, предупреждение) или ProbeError.

    429 - отказ сайта, а не поломка пути: измерить скорость нечем, поломкой не считаем."""
    if code == "429":
        return None, "сайт ограничил частоту скачивания, скорость не измерена"
    if code != "200":
        raise ProbeError("download", f"скачивание вернуло HTTP {code or '000'}")
    speed = size / seconds if seconds > 0 else 0.0
    if size < expected_bytes * 0.9:
        raise ProbeError("download", f"скачалось {size} из {expected_bytes} байт")
    if seconds > max_seconds:
        raise ProbeError("download", f"скачивание заняло {seconds:.1f} с при пороге {max_seconds} с")
    if speed < min_bps:
        raise ProbeError("download", f"скорость {speed / 1024:.0f} КБ/с ниже порога {min_bps / 1024:.0f} КБ/с")
    return speed, None


def check_download() -> tuple[float | None, str | None]:
    out = subprocess.run(
        ["curl", "--silent", "--output", "/dev/null", "--max-time", str(MAX_DOWNLOAD_SECONDS + 5),
         "--write-out", "%{http_code} %{size_download} %{time_total}", DOWNLOAD_URL],
        capture_output=True, text=True, timeout=MAX_DOWNLOAD_SECONDS + 10,
    )
    parts = (out.stdout or "").split()
    if len(parts) != 3:
        raise ProbeError("download", f"curl завершился с кодом {out.returncode}")
    code, size, seconds = parts[0], int(parts[1]), float(parts[2])
    if out.returncode != 0:
        raise ProbeError("download", f"скачивание оборвалось на {size} байтах за {seconds:.1f} с "
                                     f"(curl {out.returncode}), похоже на потерю крупных пакетов")
    return evaluate_download(code, size, seconds, expected_bytes=DOWNLOAD_BYTES,
                             max_seconds=MAX_DOWNLOAD_SECONDS, min_bps=MIN_SPEED_BPS)


def latest_handshake_age() -> float | None:
    out = subprocess.run(["awg", "show", IFACE, "latest-handshakes"],
                         capture_output=True, text=True, timeout=5)
    fields = (out.stdout or "").split()
    if out.returncode != 0 or len(fields) < 2 or fields[1] == "0":
        return None
    return time.time() - int(fields[1])


def check_handshake() -> None:
    deadline = time.monotonic() + HANDSHAKE_WAIT_SECONDS
    while True:
        age = latest_handshake_age()
        if age is not None and age < HANDSHAKE_MAX_AGE_SECONDS:
            return
        if time.monotonic() >= deadline:
            raise ProbeError("handshake", "нет рукопожатия с сервером")
        time.sleep(1)


def probe(config: dict) -> dict:
    started = time.monotonic()
    result: dict = {"state": "probed", "ok": False, "stage": None, "error": None,
                    "exit_ip": None, "speed_bps": None, "note": None}
    try:
        check_handshake()
        dns_server = DNS_SERVER or config.get("dns")
        if dns_server:
            check_dns(dns_server, DNS_NAMES)
        result["exit_ip"] = check_exit_ip(config.get("expected_exit_ips") or [])
        speed, note = check_download()
        result["speed_bps"] = round(speed) if speed is not None else None
        result["note"] = note
        result["ok"] = True
    except ProbeError as exc:
        result["stage"] = exc.stage
        result["error"] = str(exc)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result["stage"] = "internal"
        result["error"] = f"проба не выполнилась: {exc}"
    result["duration_ms"] = round((time.monotonic() - started) * 1000)
    return result


# --- интерфейс ------------------------------------------------------------

def _run(*cmd: str) -> None:
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    if out.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {(out.stderr or out.stdout).strip()}")


def default_gateway() -> str:
    out = subprocess.run(["ip", "-4", "route", "show", "default"],
                         capture_output=True, text=True, timeout=5)
    match = re.search(r"default via (\S+)", out.stdout)
    if not match:
        raise RuntimeError("в контейнере нет маршрута по умолчанию")
    return match.group(1)


def setconf_text(conf: str, endpoint_ip: str, port: int) -> str:
    """То, что сделал бы `awg-quick strip`, и подмена адреса сервера.

    awg-quick здесь не годится: ему нужен src_valid_mark, а /proc/sys в
    контейнере без SYS_ADMIN доступен только на чтение."""
    lines = []
    for line in conf.splitlines():
        key = line.split("=", 1)[0].strip().lower()
        if key in ("address", "mtu", "dns"):
            continue
        if key == "endpoint":
            line = f"Endpoint = {endpoint_ip}:{port}"
        lines.append(line)
    return "\n".join(lines) + "\n"


class Tunnel:
    def __init__(self):
        self.digest: str | None = None
        self.resolv: str | None = None

    def down(self) -> None:
        subprocess.run(["ip", "link", "del", IFACE], capture_output=True, timeout=10)
        if self.resolv is not None:
            RESOLV_CONF.write_text(self.resolv, encoding="utf-8")
            self.resolv = None
        self.digest = None

    def up(self, config: dict, digest: str) -> None:
        self.down()
        gateway = default_gateway()
        endpoint = socket.gethostbyname(ENDPOINT_HOST) if ENDPOINT_HOST else gateway

        _run("amneziawg-go", IFACE)
        with tempfile.NamedTemporaryFile("w", suffix=".conf", encoding="utf-8") as tmp:
            tmp.write(setconf_text(config["conf"], endpoint, int(config["listen_port"])))
            tmp.flush()
            _run("awg", "setconf", IFACE, tmp.name)
        _run("ip", "address", "add", config["address"], "dev", IFACE)
        _run("ip", "link", "set", IFACE, "mtu", str(config.get("mtu") or DEFAULT_MTU), "up")
        # Адрес сервера остаётся через шлюз, остальное идёт в туннель. Маршрут по
        # умолчанию не трогаем: две половины адресного пространства точнее него.
        if endpoint != gateway:
            _run("ip", "route", "replace", f"{endpoint}/32", "via", gateway)
        _run("ip", "route", "replace", "0.0.0.0/1", "dev", IFACE)
        _run("ip", "route", "replace", "128.0.0.0/1", "dev", IFACE)

        # Иначе curl разрешал бы имена встроенным DNS Docker, мимо туннеля.
        dns_server = DNS_SERVER or config.get("dns")
        if dns_server:
            self.resolv = RESOLV_CONF.read_text(encoding="utf-8")
            RESOLV_CONF.write_text(f"nameserver {dns_server}\n", encoding="utf-8")
        self.digest = digest

    def present(self) -> bool:
        return Path(f"/sys/class/net/{IFACE}").exists()


# --- цикл -----------------------------------------------------------------

def write_result(result: dict) -> None:
    result = {**result, "ts": time.time()}
    tmp = CANARY_DIR / ".result.tmp"
    tmp.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, CANARY_DIR / "result.json")


def load_config() -> tuple[dict, str] | None:
    try:
        raw = (CANARY_DIR / "config.json").read_bytes()
        return json.loads(raw), hashlib.sha256(raw).hexdigest()
    except (OSError, ValueError):
        return None


def cycle(tunnel: Tunnel) -> None:
    loaded = load_config()
    if loaded is None:
        if tunnel.digest is not None or tunnel.present():
            tunnel.down()
        write_result({"state": "idle"})
        return
    config, digest = loaded
    if digest != tunnel.digest or not tunnel.present():
        tunnel.up(config, digest)
    write_result(probe(config))


def main() -> None:
    CANARY_DIR.mkdir(parents=True, exist_ok=True)
    tunnel = Tunnel()
    while True:
        started = time.monotonic()
        try:
            cycle(tunnel)
        except Exception as exc:
            print(f"[canary] {exc}", flush=True)
            tunnel.digest = None
            write_result({"state": "probed", "ok": False, "stage": "tunnel",
                          "error": f"туннель не поднялся: {exc}"})
        time.sleep(max(1.0, INTERVAL_SECONDS - (time.monotonic() - started)))


if __name__ == "__main__":
    main()
