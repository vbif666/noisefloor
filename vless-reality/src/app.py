"""
VLESS + Reality (Xray-core) - self-provisioning endpoint with a small admin panel.

On first start:
  - generates a Reality x25519 keypair, a client UUID and a short id
  - generates an admin password (unless ADMIN_PASSWORD is set) and writes it
    to /data/INITIAL_ADMIN_PASSWORD.txt
  - writes /data/creds.json (persisted via volume)
  - renders /data/xray-config.json (with a local Stats API inbound)
  - starts the official `xray` binary as a child process
  - tails the xray access log to detect client handshakes
  - polls the local Xray Stats API to report live traffic

Web UI (PANEL_PORT, default 8001), protected with HTTP Basic auth:
  GET  /              - status page: vless:// link, QR code, traffic, settings, restart
  GET  /api/status     - JSON status
  GET  /api/qr.png     - QR code of the current vless:// link
  POST /api/settings   - update SNI / camouflage dest (restarts xray, not the container)
  POST /api/restart    - restart the whole container (relies on `restart: unless-stopped`)
"""
import base64
import html
import io
import json
import os
import re
import secrets
import subprocess
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import qrcode

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
CREDS_FILE = DATA_DIR / "creds.json"
CONFIG_FILE = DATA_DIR / "xray-config.json"
ADMIN_PW_FILE = DATA_DIR / "INITIAL_ADMIN_PASSWORD.txt"
# Лог лежит в volume, а не в слое контейнера: раньше он жил в
# /var/log/xray и обнулялся при каждом пересоздании контейнера, то есть
# разбирать вчерашний инцидент было уже нечем. Заодно теперь он попадает
# в резервные копии.
LOG_DIR = DATA_DIR / "logs"
ACCESS_LOG = LOG_DIR / "xray-access.log"
# Ротации у xray нет, а пишет он строку на каждое соединение — без
# ограничения файл со временем съедает диск.
ACCESS_LOG_MAX_BYTES = 20 * 1024 * 1024
ACCESS_LOG_CHECK_SECONDS = 60
XRAY_BIN = os.environ.get("XRAY_BIN", "/usr/local/bin/xray")
STATS_API_ADDR = "127.0.0.1:10085"

VLESS_PORT = int(os.environ.get("VLESS_PORT", "8443"))
PANEL_PORT = int(os.environ.get("PANEL_PORT", "8001"))
# dl.google.com, not www.microsoft.com: REALITY has a known upstream bug
# (XTLS/Xray-core #6356) where a stolen Certificate record >8192 bytes gets
# rejected as an invalid connection - some www.microsoft.com CDN edges
# (OCSP-stapled ones) trip it, dl.google.com doesn't. Keep this default
# working out of the box instead of pointing new deployments at a known trap.
DEFAULT_REALITY_DEST = os.environ.get("REALITY_DEST") or "dl.google.com:443"
DEFAULT_REALITY_SNI = os.environ.get("REALITY_SNI") or DEFAULT_REALITY_DEST.split(":")[0]
PUBLIC_HOST = os.environ.get("PUBLIC_HOST", "")
LABEL = os.environ.get("LABEL", "vless-reality")
# Имя переменной единое с панелью — ADMIN_USERNAME. Прежнее ADMIN_USER
# оставлено синонимом, чтобы не сломать уже развёрнутые инсталляции:
# два родственных сервиса с разными именами одной и той же настройки —
# лишний повод ошибиться при развёртывании.
ADMIN_USER = os.environ.get("ADMIN_USERNAME") or os.environ.get("ADMIN_USER") or "admin"
# Cosmetic-only page identity - deliberately generic so the browser tab /
# title doesn't reveal this is a VPN endpoint. Does not affect the vless://
# link (that still uses LABEL).
APP_NAME = os.environ.get("APP_NAME", "NOISEFLOOR")
APP_CODENAME = os.environ.get("APP_CODENAME", "Relay-01")

DATA_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

HISTORY_INTERVAL = 5  # seconds, matches poll_stats sleep
HISTORY_MAX = 1080  # 1080 * 5s = 1.5h of samples kept in memory

state = {
    "started_at": datetime.now(timezone.utc).isoformat(),
    "connected": False,
    "last_connect": None,
    "last_client_ip": None,
    "connect_count": 0,
    "xray_running": False,
    "traffic_uplink": 0,
    "traffic_downlink": 0,
    "traffic_active": False,
    "traffic_checked_at": None,
}
traffic_history: list[dict] = []
state_lock = threading.Lock()

# ---------------------------------------------------------------- auth ----

def get_admin_password() -> str:
    if ADMIN_PW_FILE.exists():
        return ADMIN_PW_FILE.read_text().strip()
    pw = os.environ.get("ADMIN_PASSWORD") or secrets.token_urlsafe(12)
    ADMIN_PW_FILE.write_text(pw + "\n")
    try:
        ADMIN_PW_FILE.chmod(0o600)
    except Exception:
        pass
    return pw


ADMIN_PASSWORD = get_admin_password()
security = HTTPBasic(auto_error=False)

SYNC_PATH = "/api/sync"


def _sync_token() -> str:
    try:
        return json.loads(CREDS_FILE.read_text()).get("sync_token", "")
    except Exception:
        return ""


def _authorise_sync(request) -> str:
    """Синхронизация ходит с токеном: у панели на соседнем сервере нет и не
    должно быть пароля администратора от этого релея."""
    expected = _sync_token()
    header = request.headers.get("authorization", "")
    presented = ""
    if header.lower().startswith("bearer "):
        presented = header[7:].strip()
    else:
        presented = request.headers.get("x-sync-token", "").strip()

    if not expected or not presented or not secrets.compare_digest(presented, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный токен синхронизации",
        )
    return "sync"


def check_auth(request: Request, credentials: HTTPBasicCredentials | None = Depends(security)):
    if request.url.path == SYNC_PATH:
        return _authorise_sync(request)

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )
    user_ok = secrets.compare_digest(credentials.username, ADMIN_USER)
    pass_ok = secrets.compare_digest(credentials.password, ADMIN_PASSWORD)
    if not (user_ok and pass_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


# ------------------------------------------------------------ provision ----

def run_x25519() -> dict:
    out = subprocess.run([XRAY_BIN, "x25519"], capture_output=True, text=True, check=True).stdout
    values = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            k = re.sub(r"\(.*?\)", "", k).strip().lower().replace(" ", "")
            values[k] = v.strip()
    priv = values.get("privatekey") or values.get("private")
    pub = values.get("publickey") or values.get("password") or values.get("public")
    if not priv or not pub:
        raise RuntimeError(f"could not parse `xray x25519` output:\n{out}")
    return {"private_key": priv, "public_key": pub}


def provision() -> dict:
    if CREDS_FILE.exists():
        creds = json.loads(CREDS_FILE.read_text())
        # backfill defaults if the file predates a field
        creds.setdefault("dest", DEFAULT_REALITY_DEST)
        creds.setdefault("sni", DEFAULT_REALITY_SNI)
        creds.setdefault("vless_port", VLESS_PORT)
        # Токен появился позже — дописываем его уже развёрнутым релеям,
        # чтобы синхронизация заработала без пересоздания ключей.
        if not creds.get("sync_token"):
            creds["sync_token"] = secrets.token_urlsafe(32)
            save_creds(creds)
        return creds
    keys = run_x25519()
    creds = {
        "uuid": str(uuid.uuid4()),
        "short_id": secrets.token_hex(8),
        "private_key": keys["private_key"],
        "public_key": keys["public_key"],
        "dest": DEFAULT_REALITY_DEST,
        "sni": DEFAULT_REALITY_SNI,
        "vless_port": VLESS_PORT,
        # Секрет для синхронизации: по нему панель на соседнем сервере
        # забирает актуальные параметры подключения и сама подстраивается
        # под них. Отдельный от пароля администратора — панели-клиенту
        # незачем иметь полный доступ к этому релею.
        "sync_token": secrets.token_urlsafe(32),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    save_creds(creds)
    return creds


def save_creds(creds: dict) -> None:
    CREDS_FILE.write_text(json.dumps(creds, indent=2))


def render_config(creds: dict) -> None:
    config = {
        "log": {"loglevel": "warning", "access": str(ACCESS_LOG)},
        "stats": {},
        "api": {"tag": "api", "services": ["StatsService"]},
        "policy": {
            # Таймауты выставлены явно, потому что умолчания движка рвут
            # длинные соединения: connIdle 300 закрывает всё, что молчит
            # пять минут (ssh, imap, вебсокеты мессенджеров), а uplinkOnly 2
            # и downlinkOnly 5 добивают вторую половину соединения сразу
            # после закрытия первой, обрезая хвост больших ответов. Те же
            # значения стоят на входе каскада в панели — плечо одно, и
            # таймауты на его концах расходиться не должны.
            "levels": {"0": {
                "statsUserUplink": True,
                "statsUserDownlink": True,
                "handshake": 8,
                "connIdle": 900,
                "uplinkOnly": 0,
                "downlinkOnly": 0,
            }},
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True},
        },
        "inbounds": [
            {
                "listen": "0.0.0.0",
                "port": creds["vless_port"],
                "protocol": "vless",
                "tag": "vless-in",
                "settings": {
                    "clients": [
                        {"id": creds["uuid"], "flow": "xtls-rprx-vision", "email": "client1"}
                    ],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "dest": creds["dest"],
                        "xver": 0,
                        "serverNames": [creds["sni"]],
                        "privateKey": creds["private_key"],
                        "shortIds": [creds["short_id"]],
                    },
                },
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
            },
            {
                "listen": "127.0.0.1",
                "port": 10085,
                "protocol": "dokodemo-door",
                "tag": "api-in",
                "settings": {"address": "127.0.0.1"},
            },
        ],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
        "routing": {
            "rules": [
                {"type": "field", "inboundTag": ["api-in"], "outboundTag": "api"}
            ]
        },
    }
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def build_vless_url(creds: dict, host: str) -> str:
    params = {
        "type": "tcp",
        "security": "reality",
        "pbk": creds["public_key"],
        "fp": "chrome",
        "sni": creds["sni"],
        "sid": creds["short_id"],
        "flow": "xtls-rprx-vision",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{creds['uuid']}@{host}:{creds['vless_port']}?{query}#{quote(LABEL)}"


# --------------------------------------------------------------- xray -----

xray_proc: subprocess.Popen | None = None
xray_lock = threading.Lock()


def start_xray():
    global xray_proc
    with xray_lock:
        xray_proc = subprocess.Popen([XRAY_BIN, "run", "-config", str(CONFIG_FILE)])
    with state_lock:
        state["xray_running"] = True


def stop_xray():
    global xray_proc
    with xray_lock:
        if xray_proc and xray_proc.poll() is None:
            xray_proc.terminate()
            try:
                xray_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                xray_proc.kill()
        with state_lock:
            state["xray_running"] = False


def restart_xray():
    """Apply a config change without restarting the whole container."""
    stop_xray()
    time.sleep(0.5)
    start_xray()


IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]):\d+ accepted")


def tail_access_log(stop_event: threading.Event):
    ACCESS_LOG.touch(exist_ok=True)
    with ACCESS_LOG.open("r") as f:
        f.seek(0, io.SEEK_END)
        while not stop_event.is_set():
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            m = IP_RE.search(line)
            if m and "vless-in" in line:
                with state_lock:
                    state["connected"] = True
                    state["last_connect"] = datetime.now(timezone.utc).isoformat()
                    state["last_client_ip"] = m.group(1)
                    state["connect_count"] += 1


def poll_stats(stop_event: threading.Event):
    prev_total = None
    while not stop_event.is_set():
        time.sleep(5)
        try:
            out = subprocess.run(
                [XRAY_BIN, "api", "statsquery", f"-server={STATS_API_ADDR}",
                 "-pattern", "inbound>>>vless-in>>>traffic"],
                capture_output=True, text=True, timeout=5,
            )
            if out.returncode != 0:
                continue
            data = json.loads(out.stdout)
            up = down = 0
            for item in data.get("stat", []):
                name = item.get("name", "")
                val = int(item.get("value", 0))
                if name.endswith("uplink"):
                    up = val
                elif name.endswith("downlink"):
                    down = val
            total = up + down
            active = prev_total is not None and total > prev_total
            prev_total = total
            now = datetime.now(timezone.utc)
            with state_lock:
                state["traffic_uplink"] = up
                state["traffic_downlink"] = down
                state["traffic_active"] = active
                state["traffic_checked_at"] = now.isoformat()
                traffic_history.append({"t": now.isoformat(), "up": up, "down": down})
                if len(traffic_history) > HISTORY_MAX:
                    del traffic_history[: len(traffic_history) - HISTORY_MAX]
        except Exception:
            continue


def rotate_access_log(stop_event: threading.Event):
    """Грубая ротация: при превышении лимита обрезаем файл на месте.

    Полноценная ротация потребовала бы перезапуска xray (он держит файл
    открытым), а это разрыв всех клиентских соединений ради уборки логов.
    Лог нужен, чтобы разобрать последний инцидент, а не как вечный журнал,
    поэтому "последние N мегабайт" — разумный размен."""
    while not stop_event.is_set():
        stop_event.wait(ACCESS_LOG_CHECK_SECONDS)
        try:
            if ACCESS_LOG.exists() and ACCESS_LOG.stat().st_size > ACCESS_LOG_MAX_BYTES:
                with ACCESS_LOG.open("w"):
                    pass
        except OSError:
            continue


def watchdog(stop_event: threading.Event):
    while not stop_event.is_set():
        time.sleep(5)
        if xray_proc is not None and xray_proc.poll() is not None:
            with state_lock:
                state["xray_running"] = False
            if not stop_event.is_set():
                start_xray()


_stop_event = threading.Event()


@asynccontextmanager
async def lifespan(app: FastAPI):
    creds = provision()
    render_config(creds)
    start_xray()
    threads = [
        threading.Thread(target=tail_access_log, args=(_stop_event,), daemon=True),
        threading.Thread(target=watchdog, args=(_stop_event,), daemon=True),
        threading.Thread(target=poll_stats, args=(_stop_event,), daemon=True),
        threading.Thread(target=rotate_access_log, args=(_stop_event,), daemon=True),
    ]
    for t in threads:
        t.start()
    try:
        yield
    finally:
        _stop_event.set()
        stop_xray()


app = FastAPI(lifespan=lifespan, dependencies=[Depends(check_auth)])


def current_host() -> str:
    if PUBLIC_HOST:
        return PUBLIC_HOST
    try:
        return subprocess.run(
            ["sh", "-c", "curl -s --max-time 3 https://ifconfig.me || true"],
            capture_output=True, text=True,
        ).stdout.strip() or "YOUR-SERVER-IP"
    except Exception:
        return "YOUR-SERVER-IP"


def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def human_rate(bytes_per_sec: float) -> str:
    return f"{human_bytes(int(bytes_per_sec))}/s"


# ------------------------------------------------------------- routes -----

@app.get("/api/status")
def api_status():
    with state_lock:
        s = dict(state)
    creds = json.loads(CREDS_FILE.read_text()) if CREDS_FILE.exists() else {}
    host = current_host()
    s["vless_url"] = build_vless_url(creds, host) if creds else None
    s["sni"] = creds.get("sni")
    s["dest"] = creds.get("dest")
    s["port"] = creds.get("vless_port")
    return JSONResponse(s)


@app.get("/api/metrics", response_class=Response)
def api_metrics():
    """Метрики в формате Prometheus — те же, что отдаёт панель, чтобы за
    обоими сервисами следить одинаково."""
    with state_lock:
        s = dict(state)
    lines = [
        "# HELP noisefloor_relay_xray_up Жив ли процесс xray",
        "# TYPE noisefloor_relay_xray_up gauge",
        f"noisefloor_relay_xray_up {int(bool(s['xray_running']))}",
        "# HELP noisefloor_relay_client_connected Было ли хоть одно подключение клиента",
        "# TYPE noisefloor_relay_client_connected gauge",
        f"noisefloor_relay_client_connected {int(bool(s['connected']))}",
        "# HELP noisefloor_relay_connections_total Всего рукопожатий клиентов",
        "# TYPE noisefloor_relay_connections_total counter",
        f"noisefloor_relay_connections_total {s['connect_count']}",
        "# HELP noisefloor_relay_uplink_bytes_total Отправлено через релей",
        "# TYPE noisefloor_relay_uplink_bytes_total counter",
        f"noisefloor_relay_uplink_bytes_total {s['traffic_uplink']}",
        "# HELP noisefloor_relay_downlink_bytes_total Получено через релей",
        "# TYPE noisefloor_relay_downlink_bytes_total counter",
        f"noisefloor_relay_downlink_bytes_total {s['traffic_downlink']}",
        "# HELP noisefloor_relay_traffic_active Шёл ли трафик на последнем замере",
        "# TYPE noisefloor_relay_traffic_active gauge",
        f"noisefloor_relay_traffic_active {int(bool(s['traffic_active']))}",
    ]
    return Response(content="\n".join(lines) + "\n", media_type="text/plain; charset=utf-8")


@app.get("/api/traffic-history")
def api_traffic_history():
    with state_lock:
        hist = list(traffic_history)
    return JSONResponse(hist)


@app.get(SYNC_PATH)
def api_sync():
    """Текущие параметры подключения к этому релею — для панели на соседнем
    сервере.

    Смысл в том, чтобы SNI и camouflage dest не приходилось держать
    одинаковыми вручную: меняем их здесь, панель забирает изменение сама.
    Раньше после смены dest каскад молча переставал пропускать трафик,
    пока кто-нибудь не обновит ссылку на первом сервере руками."""
    creds = json.loads(CREDS_FILE.read_text())
    host = current_host()
    return JSONResponse({
        "label": LABEL,
        "codename": APP_CODENAME,
        "host": host,
        "port": creds["vless_port"],
        "uuid": creds["uuid"],
        "public_key": creds["public_key"],
        "short_id": creds["short_id"],
        "sni": creds["sni"],
        "dest": creds["dest"],
        "flow": "xtls-rprx-vision",
        "fp": "chrome",
        # Готовая ссылка: собирает её тот, кто знает свои настройки, —
        # меньше шансов, что стороны разойдутся в мелочах.
        "vless_url": build_vless_url(creds, host),
    })


@app.post("/api/sync/rotate")
def api_sync_rotate():
    """Сменить токен. Прежний перестаёт работать сразу, поэтому на панели
    соседнего сервера токен придётся обновить."""
    creds = json.loads(CREDS_FILE.read_text())
    creds["sync_token"] = secrets.token_urlsafe(32)
    save_creds(creds)
    return JSONResponse({"sync_token": creds["sync_token"]})


@app.get("/api/qr.png")
def api_qr():
    creds = json.loads(CREDS_FILE.read_text())
    url = build_vless_url(creds, current_host())
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return Response(content=buf.getvalue(), media_type="image/png")


@app.post("/api/settings")
def api_settings(dest: str = Form(...), sni: str = Form(...)):
    dest = dest.strip()
    sni = sni.strip() or dest.split(":")[0]
    if ":" not in dest:
        dest = f"{dest}:443"
    creds = json.loads(CREDS_FILE.read_text())
    creds["dest"] = dest
    creds["sni"] = sni
    save_creds(creds)
    render_config(creds)
    restart_xray()
    return RedirectResponse(url="/", status_code=303)


@app.post("/api/restart")
def api_restart():
    """Restart the whole container: exit the process and let
    `restart: unless-stopped` in docker-compose bring it back."""
    def _do_restart():
        time.sleep(0.5)
        stop_xray()
        os._exit(0)

    threading.Thread(target=_do_restart, daemon=True).start()
    return JSONResponse({"restarting": True})


PAGE_TEMPLATE = r"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>@@APP_NAME@@ &middot; @@APP_CODENAME@@</title>
<link rel="icon" href="data:," />
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet" />
<style>
:root {
  --bg: #0a0c10;
  --surface: #12151b;
  --surface-2: #171b22;
  --surface-3: #1e232c;
  --line: #242a34;
  --line-soft: #1a1e26;

  --text: #e7e9ed;
  --text-dim: #838b99;
  --text-faint: #4b515c;

  --signal: #ff9f45;
  --signal-strong: #ffb768;
  --signal-dim: rgba(255, 159, 69, 0.13);
  --signal-line: rgba(255, 159, 69, 0.35);

  --good: #4fd1a5;
  --good-dim: rgba(79, 209, 165, 0.13);
  --danger: #e5484d;
  --danger-dim: rgba(229, 72, 77, 0.13);
  --danger-strong: #ff6b70;

  --font-display: "IBM Plex Mono", ui-monospace, "SFMono-Regular", Menlo, monospace;
  --font-body: "IBM Plex Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --font-mono: "IBM Plex Mono", ui-monospace, "SFMono-Regular", Menlo, monospace;

  --radius-sm: 6px;
  --radius-md: 10px;
  --radius-lg: 16px;
  --ease: cubic-bezier(0.2, 0.8, 0.2, 1);
}
* { box-sizing: border-box; }
html, body { height: 100%; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-body);
  font-size: 15px;
  line-height: 1.5;
  background-image:
    radial-gradient(circle at 15% -10%, rgba(255, 159, 69, 0.06), transparent 45%),
    radial-gradient(circle at 85% 0%, rgba(79, 209, 165, 0.035), transparent 40%);
  background-attachment: fixed;
}
h1, h2, h3 { font-family: var(--font-display); font-weight: 600; letter-spacing: -0.01em; margin: 0; }
p { margin: 0; }
::selection { background: var(--signal-dim); color: var(--signal-strong); }
.mono { font-family: var(--font-mono); }
.eyebrow {
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--text-faint);
}

.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 28px;
  border-bottom: 1px solid var(--line-soft);
}
.wordmark { display: flex; align-items: center; gap: 10px; }
.wordmark .dot {
  width: 8px; height: 8px; border-radius: 50%;
  background: var(--signal);
  box-shadow: 0 0 12px 1px var(--signal-line);
}
.wordmark span { font-family: var(--font-display); font-weight: 600; font-size: 15px; letter-spacing: 0.03em; }
.status-pill {
  display: inline-flex; align-items: center; gap: 7px;
  font-family: var(--font-mono); font-size: 12px; color: var(--text-dim);
  background: var(--surface-2); border: 1px solid var(--line);
  padding: 6px 12px; border-radius: 999px; white-space: nowrap;
}
.status-pill .indicator { width: 7px; height: 7px; border-radius: 50%; background: var(--text-faint); }
.status-pill.is-up .indicator { background: var(--good); box-shadow: 0 0 8px 0 rgba(79, 209, 165, 0.6); }
.status-pill.is-down .indicator { background: var(--text-faint); }

.signal-strip {
  position: relative; height: 26px; overflow: hidden;
  border-bottom: 1px solid var(--line-soft);
  background: repeating-linear-gradient(90deg, var(--line-soft) 0 1px, transparent 1px 46px);
  background-position: 8px 0;
}
.signal-strip .packet {
  position: absolute; top: 50%; transform: translateY(-50%);
  width: 14px; height: 4px; border-radius: 2px;
  background: var(--text-faint); opacity: 0.55; animation: drift linear infinite;
}
.signal-strip .packet.is-signal {
  background: var(--signal); box-shadow: 0 0 8px 0 var(--signal-line);
  opacity: 0.95; height: 5px; width: 20px;
}
@keyframes drift { from { left: -6%; } to { left: 106%; } }
@media (prefers-reduced-motion: reduce) { .signal-strip .packet { animation: none; display: none; } }

main { max-width: 880px; margin: 0 auto; padding: 24px 20px 60px; display: flex; flex-direction: column; gap: 16px; }

.panel { background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius-lg); }
.panel-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 18px 20px; border-bottom: 1px solid var(--line-soft);
}
.panel-header h2 { font-size: 14px; letter-spacing: 0.02em; }
.panel-body { padding: 20px; }

.overview-row { display: flex; gap: 24px; align-items: flex-start; flex-wrap: wrap; }
.stat-grid {
  flex: 1; min-width: 240px;
  display: grid; grid-template-columns: 1fr 1fr; gap: 10px 20px;
}
.stat-item { padding: 2px 0; }
.stat-item .eyebrow { margin-bottom: 4px; }
.stat-value { font-size: 13.5px; color: var(--text); }
.stat-value.mono { font-size: 13px; }

.key-display {
  display: flex; align-items: center; gap: 8px;
  background: var(--surface-2); border: 1px solid var(--line); border-radius: var(--radius-sm);
  padding: 10px 12px; font-family: var(--font-mono); font-size: 12.5px; color: var(--text-dim);
  word-break: break-all; width: 100%;
}

.field { margin-bottom: 16px; }
.field:last-child { margin-bottom: 0; }
.field label { display: block; font-size: 12px; color: var(--text-dim); margin-bottom: 6px; }
.field input, .field textarea {
  width: 100%; background: var(--surface-2); border: 1px solid var(--line); border-radius: var(--radius-sm);
  padding: 10px 12px; font-size: 14px; font-family: inherit; color: inherit;
  transition: border-color 0.15s var(--ease), background 0.15s var(--ease);
}
.field input:focus, .field textarea:focus { outline: none; border-color: var(--signal); background: var(--surface-3); }
.field-hint { font-size: 11.5px; color: var(--text-faint); margin-top: 6px; line-height: 1.5; }
.field-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }

.btn {
  appearance: none; border: 1px solid var(--line); background: var(--surface-2); color: var(--text);
  font-family: var(--font-body); font-size: 13.5px; font-weight: 500; padding: 9px 16px;
  border-radius: var(--radius-sm); cursor: pointer; display: inline-flex; align-items: center; gap: 8px;
  transition: border-color 0.15s var(--ease), background 0.15s var(--ease), transform 0.1s var(--ease);
}
.btn:hover { border-color: #3a4150; background: var(--surface-3); }
.btn:active { transform: translateY(1px); }
.btn-primary { background: var(--signal); border-color: var(--signal); color: #201203; font-weight: 600; }
.btn-primary:hover { background: var(--signal-strong); border-color: var(--signal-strong); }
.btn-danger { color: var(--danger-strong); }
.btn-danger:hover { background: var(--danger-dim); border-color: rgba(229, 72, 77, 0.4); }
.btn-sm { padding: 6px 11px; font-size: 12.5px; }

.chart-wrap { position: relative; }
canvas.chart-canvas { width: 100%; height: 140px; display: block; }
.chart-legend { display: flex; gap: 20px; margin-top: 14px; flex-wrap: wrap; }
.legend-item { display: flex; align-items: center; gap: 7px; font-family: var(--font-mono); font-size: 12px; color: var(--text-dim); }
.legend-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.legend-dot.up { background: var(--signal); box-shadow: 0 0 8px 0 var(--signal-line); }
.legend-dot.down { background: var(--good); box-shadow: 0 0 7px 0 rgba(79, 209, 165, 0.6); }
.legend-value { color: var(--text); font-weight: 600; }
.chart-empty { color: var(--text-faint); font-size: 12.5px; text-align: center; padding: 46px 0; }
</style></head>
<body>

<header class="topbar">
  <div class="wordmark"><span class="dot"></span><span>@@APP_NAME@@ &middot; @@APP_CODENAME@@</span></div>
  <span id="status-pill" class="status-pill"><span class="indicator"></span><span id="status-pill-text">@@STATUS_TEXT@@</span></span>
</header>

<div class="signal-strip" id="signal-strip" aria-hidden="true"></div>

<main>

  <div class="panel">
    <div class="panel-header"><h2>Обзор</h2></div>
    <div class="panel-body">
      <div class="overview-row">
        <div class="stat-grid">
          <div class="stat-item"><span class="eyebrow">SNI</span><div class="stat-value mono">@@SNI@@</div></div>
          <div class="stat-item"><span class="eyebrow">Camouflage dest</span><div class="stat-value mono">@@DEST@@</div></div>
          <div class="stat-item"><span class="eyebrow">Порт</span><div class="stat-value mono">@@PORT@@</div></div>
          <div class="stat-item"><span class="eyebrow">xray</span><div class="stat-value" id="stat-xray">@@XRAY_STATUS@@</div></div>
          <div class="stat-item"><span class="eyebrow">Подключений</span><div class="stat-value mono" id="stat-connect-count">@@CONNECT_COUNT@@</div></div>
          <div class="stat-item"><span class="eyebrow">Последнее</span><div class="stat-value mono" id="stat-last-connect">@@LAST_CONNECT@@</div></div>
          <div class="stat-item"><span class="eyebrow">IP клиента</span><div class="stat-value mono" id="stat-client-ip">@@CLIENT_IP@@</div></div>
          <div class="stat-item"><span class="eyebrow">Всего трафика</span><div class="stat-value mono" id="stat-traffic-total">@@TRAFFIC_TOTAL@@</div></div>
        </div>
      </div>
      <div class="field" style="margin-top:20px; margin-bottom:0;">
        <label>Токен синхронизации</label>
        <div class="key-display" id="sync-token" onclick="selectText(this)">@@SYNC_TOKEN@@</div>
        <p class="field-hint">
          Вставьте его в панель первого сервера — вкладка «Сервер», блок «Каскад».
          Тогда SNI и camouflage dest не нужно держать одинаковыми вручную:
          меняете их здесь, панель забирает изменение сама.
          Ссылка подключения и QR-код здесь намеренно не показываются: в ссылке
          лежит UUID, то есть готовый доступ к этому релею, а для связки узлов
          достаточно токена.
          <button type="button" class="btn btn-sm" style="margin-left:8px;"
                  onclick="rotateToken()">Сменить</button>
        </p>
      </div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-header">
      <h2>Трафик</h2>
      <span class="eyebrow" id="chart-range-label">последний час</span>
    </div>
    <div class="panel-body">
      <div class="chart-wrap">
        <canvas class="chart-canvas" id="traffic-chart"></canvas>
        <div class="chart-empty" id="chart-empty" hidden>ещё нет данных — соберём график за пару минут</div>
      </div>
      <div class="chart-legend">
        <span class="legend-item"><span class="legend-dot up"></span>исходящий (к клиенту) <span class="legend-value" id="legend-up">—</span></span>
        <span class="legend-item"><span class="legend-dot down"></span>входящий (от клиента) <span class="legend-value" id="legend-down">—</span></span>
      </div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-header"><h2>Настройки маскировки</h2></div>
    <div class="panel-body">
      <form method="post" action="/api/settings">
        <div class="field-row">
          <div class="field">
            <label for="f-dest">Camouflage dest (host:port реального TLS-сайта)</label>
            <input id="f-dest" type="text" name="dest" value="@@DEST_RAW@@" required>
          </div>
          <div class="field">
            <label for="f-sni">SNI (обычно = хосту из dest)</label>
            <input id="f-sni" type="text" name="sni" value="@@SNI_RAW@@" required>
          </div>
        </div>
        <button type="submit" class="btn btn-primary">Сохранить и применить</button>
      </form>
    </div>
  </div>

  <div class="panel">
    <div class="panel-header"><h2>Управление</h2></div>
    <div class="panel-body">
      <button class="btn btn-danger btn-sm" onclick="if(confirm('Перезапустить контейнер?')){fetch('/api/restart',{method:'POST'}).then(()=>setTimeout(()=>location.reload(),4000))}">Перезапустить контейнер</button>
    </div>
  </div>

</main>

<script>
function selectText(el) {
  const range = document.createRange();
  range.selectNodeContents(el);
  const sel = window.getSelection();
  sel.removeAllRanges();
  sel.addRange(range);
}

async function rotateToken() {
  if (!confirm("Сменить токен? Панель, которая синхронизируется с этим релеем, "
             + "перестанет получать обновления, пока вы не впишете новый токен.")) return;
  try {
    const res = await fetch("/api/sync/rotate", { method: "POST" });
    const data = await res.json();
    document.getElementById("sync-token").textContent = data.sync_token;
  } catch (e) {
    alert("Не удалось сменить токен: " + e.message);
  }
}

function humanBytes(n) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  n = Math.max(0, n);
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n.toFixed(0) : n.toFixed(1)) + " " + units[i];
}
function humanRate(bps) { return humanBytes(bps) + "/s"; }

// --------------------------------------------------------- signal strip ----
(function initSignalStrip() {
  const strip = document.getElementById("signal-strip");
  const COUNT = 14;
  for (let i = 0; i < COUNT; i++) {
    const p = document.createElement("div");
    p.className = "packet";
    p.style.top = (14 + Math.random() * 70) + "%";
    p.style.animationDuration = (6 + Math.random() * 10) + "s";
    p.style.animationDelay = (-Math.random() * 12) + "s";
    strip.appendChild(p);
  }
})();

// -------------------------------------------------------------- status ----
async function pollStatus() {
  try {
    const r = await fetch("/api/status", { cache: "no-store" });
    const s = await r.json();
    const pill = document.getElementById("status-pill");
    const pillText = document.getElementById("status-pill-text");
    if (s.connected) {
      pill.classList.add("is-up"); pill.classList.remove("is-down");
      pillText.textContent = "подключено";
    } else {
      pill.classList.add("is-down"); pill.classList.remove("is-up");
      pillText.textContent = "ожидание подключения";
    }
    document.getElementById("stat-xray").textContent = s.xray_running ? "работает" : "остановлен";
    document.getElementById("stat-connect-count").textContent = s.connect_count;
    document.getElementById("stat-last-connect").textContent = s.last_connect || "—";
    document.getElementById("stat-client-ip").textContent = s.last_client_ip || "—";
    document.getElementById("stat-traffic-total").textContent = humanBytes(s.traffic_uplink + s.traffic_downlink);
  } catch (e) { /* сеть моргнула — подождём следующего тика */ }
}

// --------------------------------------------------------------- chart ----
const chartState = { hist: [] };

async function pollHistory() {
  try {
    const r = await fetch("/api/traffic-history", { cache: "no-store" });
    chartState.hist = await r.json();
    drawChart();
  } catch (e) { /* сеть моргнула — подождём следующего тика */ }
}

function drawChart() {
  const canvas = document.getElementById("traffic-chart");
  const empty = document.getElementById("chart-empty");
  const hist = chartState.hist;

  // cumulative counters -> per-interval rate series
  const upRates = [], downRates = [];
  for (let i = 1; i < hist.length; i++) {
    const dt = (new Date(hist[i].t) - new Date(hist[i - 1].t)) / 1000;
    if (dt <= 0) continue;
    upRates.push(Math.max(0, (hist[i].up - hist[i - 1].up) / dt));
    downRates.push(Math.max(0, (hist[i].down - hist[i - 1].down) / dt));
  }

  const lastUp = upRates.length ? upRates[upRates.length - 1] : 0;
  const lastDown = downRates.length ? downRates[downRates.length - 1] : 0;
  document.getElementById("legend-up").textContent = humanRate(lastUp);
  document.getElementById("legend-down").textContent = humanRate(lastDown);

  if (upRates.length < 2) {
    empty.hidden = false;
    canvas.style.visibility = "hidden";
    return;
  }
  empty.hidden = true;
  canvas.style.visibility = "visible";

  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth || canvas.parentElement.clientWidth;
  const h = canvas.clientHeight || 140;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  const maxVal = Math.max(1, ...upRates, ...downRates) * 1.15;
  const stepX = w / (upRates.length - 1);
  const toY = (v) => h - 6 - (v / maxVal) * (h - 14);

  // faint horizontal gridlines
  ctx.strokeStyle = "rgba(255,255,255,0.05)";
  ctx.lineWidth = 1;
  for (let g = 1; g <= 3; g++) {
    const y = Math.round(h - (g / 4) * h) + 0.5;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }

  function drawSeries(series, strokeColor, fillColor) {
    ctx.beginPath();
    series.forEach((v, idx) => {
      const x = idx * stepX, y = toY(v);
      if (idx === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.lineTo((series.length - 1) * stepX, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    ctx.fillStyle = fillColor;
    ctx.fill();

    ctx.beginPath();
    series.forEach((v, idx) => {
      const x = idx * stepX, y = toY(v);
      if (idx === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = 1.6;
    ctx.stroke();
  }

  drawSeries(downRates, "#4fd1a5", "rgba(79, 209, 165, 0.14)");
  drawSeries(upRates, "#ff9f45", "rgba(255, 159, 69, 0.14)");
}

pollStatus(); pollHistory();
setInterval(pollStatus, 4000);
setInterval(pollHistory, 5000);
window.addEventListener("resize", drawChart);
</script>
</body></html>"""


@app.get("/", response_class=HTMLResponse)
def index(response: Response):
    # Страница собирается на лету, но без этого заголовка браузер вправе
    # показать свою старую копию — и после обновления образа человек видит
    # прежний интерфейс, не понимая почему.
    response.headers["Cache-Control"] = "no-cache"
    with state_lock:
        s = dict(state)
    creds = json.loads(CREDS_FILE.read_text()) if CREDS_FILE.exists() else {}
    # current_host() здесь больше не зовём: при пустом PUBLIC_HOST он ходил
    # к ifconfig.me при КАЖДОМ открытии страницы, а страница опрашивается
    # дашбордом каждые несколько секунд. Ссылка на странице больше не нужна: она содержит UUID, то есть
    # готовый доступ к релею. Получить её при необходимости можно через
    # /api/status — там она под паролем администратора.
    status_text = "подключено" if s["connected"] else "ожидание подключения"
    status_pill_class = "is-up" if s["connected"] else "is-down"
    last = s["last_connect"] or "—"
    ip = s["last_client_ip"] or "—"
    traffic_total = human_bytes(s["traffic_uplink"] + s["traffic_downlink"])

    page_html = PAGE_TEMPLATE
    replacements = {
        "@@APP_NAME@@": APP_NAME,
        "@@APP_CODENAME@@": APP_CODENAME,
        "@@STATUS_TEXT@@": status_text,
        "@@SNI@@": html.escape(creds.get("sni", "-")),
        "@@DEST@@": html.escape(creds.get("dest", "-")),
        "@@PORT@@": str(creds.get("vless_port", "-")),
        "@@XRAY_STATUS@@": "работает" if s["xray_running"] else "остановлен",
        "@@CONNECT_COUNT@@": str(s["connect_count"]),
        "@@LAST_CONNECT@@": html.escape(last),
        "@@CLIENT_IP@@": html.escape(ip),
        "@@TRAFFIC_TOTAL@@": traffic_total,
        "@@SYNC_TOKEN@@": html.escape(creds.get("sync_token", "—")),
        "@@DEST_RAW@@": html.escape(creds.get("dest", ""), quote=True),
        "@@SNI_RAW@@": html.escape(creds.get("sni", ""), quote=True),
    }
    for token, value in replacements.items():
        page_html = page_html.replace(token, value)
    # status-pill needs its class set on the initial (pre-JS) paint too
    page_html = page_html.replace('id="status-pill" class="status-pill"',
                                   f'id="status-pill" class="status-pill {status_pill_class}"')
    return page_html
