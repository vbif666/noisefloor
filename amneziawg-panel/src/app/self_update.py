"""
Обновление самой панели: узнать, что вышла новая версия, и попросить хост её
поставить.

Это не про amneziawg-go и xray по отдельности (см. awg_update.py) — их
версии закреплены в образе, и обновляются они только вместе с ним. Здесь
речь про образ целиком: панель знает, из какого коммита собрана, и умеет
сравнить себя с тем, что опубликовано.

Два канала:
  stable — релизы GitHub (тег vX.Y.Z + заметки). Плашка появляется, когда
           автор сознательно сказал «готово», а текст в ней — его заметки.
  latest — каждый коммит в master. Свежее, но без гарантий; для тех, кто
           хочет.

Само обновление панель не делает: контейнер не может перезапустить себя,
а давать веб-панели docker.sock — значит отдать ей root на хосте. Вместо
этого она кладёт файл-запрос в каталог данных, а хостовый агент
(noisefloor-agent, ставится установщиком) по нему делает pull и up,
проверяет здоровье и при неудаче откатывается. Результат агент пишет
рядом — панель его показывает.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from .config import DATA_DIR, settings

REPO = "vbif666/noisefloor"
IMAGE = "vbif666/noisefloor-amneziawg-panel"

# Файлы, через которые панель разговаривает с хостовым агентом.
REQUEST_FILE = DATA_DIR / "update-request.json"   # панель → агент
RESULT_FILE = DATA_DIR / "update-result.json"     # агент → панель
AGENT_FILE = DATA_DIR / "agent.json"              # есть ли агент вообще

CHECK_INTERVAL_SECONDS = 6 * 3600
HTTP_TIMEOUT = 10

_RELEASE_TAG = re.compile(r"^v\d+\.\d+\.\d+$")


@dataclass
class Build:
    version: str
    sha: str
    date: str

    @property
    def is_release(self) -> bool:
        return bool(_RELEASE_TAG.match(self.version))

    @property
    def is_dev(self) -> bool:
        return self.version == "dev" or self.sha == "unknown"


@dataclass
class Available:
    version: str
    sha: str | None
    date: str | None
    notes: str
    url: str


@dataclass
class State:
    current: Build
    channel: str
    components: dict[str, str]
    checked_at: str | None = None
    check_error: str | None = None
    latest: Available | None = None
    available: bool = False
    agent_available: bool = False
    pending: bool = False
    last_result: dict | None = None

    def as_dict(self) -> dict:
        d = asdict(self)
        return d


_lock = threading.Lock()
_state: State | None = None


def current_build() -> Build:
    return Build(
        version=os.environ.get("NOISEFLOOR_VERSION") or "dev",
        sha=os.environ.get("NOISEFLOOR_BUILD_SHA") or "unknown",
        date=os.environ.get("NOISEFLOOR_BUILD_DATE") or "unknown",
    )


def components() -> dict[str, str]:
    """Версии того, что зашито в образ. Обновляются только вместе с ним."""
    return {
        "amneziawg-go": os.environ.get("AWG_GO_BUILT_REF") or "?",
        "amneziawg-tools": os.environ.get("AWG_TOOLS_BUILT_REF") or "?",
        "xray": os.environ.get("XRAY_BUILT_REF") or "?",
        "geoip": os.environ.get("GEOIP_BUILT_REF") or "?",
    }


def _channel() -> str:
    value = (getattr(settings, "update_channel", "stable") or "stable").strip().lower()
    return value if value in ("stable", "latest") else "stable"


def _get_json(url: str, headers: dict | None = None):
    req = urllib.request.Request(url, headers={
        "Accept": "application/json",
        "User-Agent": "noisefloor-panel",
        **(headers or {}),
    })
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return json.load(resp)


def _gh_headers() -> dict:
    token = os.environ.get("AWG_UPDATE_GITHUB_PAT", "")
    return {"Authorization": f"token {token}"} if token else {}


# ---------------------------------------------------------------- stable ---

def _latest_release() -> Available | None:
    try:
        data = _get_json(f"https://api.github.com/repos/{REPO}/releases/latest", _gh_headers())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None  # релизов ещё не было — это не ошибка
        raise
    tag = data.get("tag_name")
    if not tag:
        return None
    return Available(
        version=tag,
        sha=None,
        date=data.get("published_at"),
        notes=(data.get("body") or "").strip(),
        url=data.get("html_url") or f"https://github.com/{REPO}/releases/tag/{tag}",
    )


def _release_is_newer(current: Build, latest: Available) -> bool:
    if current.is_dev:
        # Сборка без штампа: сравнивать не с чем, но раз есть релиз — пусть
        # оператор о нём знает.
        return True
    if current.is_release:
        return latest.version != current.version
    # Между релизами (v1.0.0-3-gabc или сборка с правками): новее ли релиз
    # самой сборки — по дате.
    return bool(latest.date and current.date != "unknown" and latest.date > current.date)


# ---------------------------------------------------------------- latest ---

def _latest_commit_image() -> tuple[str, str | None, str | None] | None:
    """Коммит, из которого собран текущий :latest в Docker Hub.

    Реестр не знает про коммиты, но CI кладёт рядом с latest тег sha-XXXX
    с тем же digest — по совпадению digest и находим."""
    data = _get_json(f"https://hub.docker.com/v2/repositories/{IMAGE}/tags?page_size=100")
    tags = {t["name"]: t for t in data.get("results", [])}
    latest = tags.get("latest")
    if not latest:
        return None
    digest = latest.get("digest")
    sha = None
    for name, tag in tags.items():
        if name.startswith("sha-") and tag.get("digest") == digest:
            sha = name[len("sha-"):]
            break
    return digest or "", sha, latest.get("last_updated")


def _commits_between(base: str, head: str) -> str:
    try:
        data = _get_json(f"https://api.github.com/repos/{REPO}/compare/{base}...{head}", _gh_headers())
    except Exception:
        return ""
    lines = []
    for c in data.get("commits", []):
        title = (c.get("commit", {}).get("message") or "").splitlines()[0]
        lines.append(f"- {title}")
    return "\n".join(lines)


def _latest_master(current: Build) -> tuple[Available | None, bool]:
    found = _latest_commit_image()
    if not found:
        return None, False
    _digest, sha, updated = found
    if not sha:
        # latest есть, а тега sha-… рядом нет: образ собран не CI, а руками.
        return Available(version="latest", sha=None, date=updated, notes="", url=f"https://hub.docker.com/r/{IMAGE}/tags"), False
    if current.is_dev:
        newer = True
    else:
        # Короткие хеши бывают разной длины: сравниваем по префиксу.
        same = current.sha.startswith(sha) or sha.startswith(current.sha)
        newer = not same
    notes = _commits_between(current.sha, sha) if newer and not current.is_dev else ""
    return Available(version=f"sha-{sha}", sha=sha, date=updated,
                     notes=notes, url=f"https://github.com/{REPO}/commits/{sha}"), newer


# ----------------------------------------------------------------- state ---

def _read_json(path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _refresh_files(state: State) -> None:
    state.agent_available = AGENT_FILE.exists()
    state.pending = REQUEST_FILE.exists()
    state.last_result = _read_json(RESULT_FILE)


def check() -> State:
    """Сходить в сеть и обновить состояние. Ошибка сети — не авария:
    остаётся прошлый результат и текст ошибки."""
    global _state
    current = current_build()
    channel = _channel()
    with _lock:
        state = _state or State(current=current, channel=channel, components=components())
        state.current, state.channel = current, channel
    try:
        if channel == "latest":
            latest, newer = _latest_master(current)
        else:
            latest = _latest_release()
            newer = bool(latest) and _release_is_newer(current, latest)
        with _lock:
            state.latest, state.available, state.check_error = latest, newer, None
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as exc:
        with _lock:
            state.check_error = f"не удалось проверить: {exc}"
    with _lock:
        state.checked_at = datetime.now(timezone.utc).isoformat()
        _refresh_files(state)
        _state = state
        return state


def status() -> State:
    global _state
    with _lock:
        if _state is None:
            _state = State(current=current_build(), channel=_channel(), components=components())
        _refresh_files(_state)
        return _state


def request_update() -> tuple[bool, str]:
    """Попросить хост обновить панель. Возвращает (ok, сообщение)."""
    state = status()
    if not state.agent_available:
        return False, (
            "На хосте нет агента обновлений — обновите вручную: "
            "docker compose pull && docker compose up -d (или запустите установщик заново)"
        )
    if state.pending:
        return True, "Запрос уже отправлен, агент обновляет"
    target = state.latest.version if state.latest else "latest"
    payload = {
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "from": asdict(state.current),
        "target": target,
        "channel": state.channel,
    }
    try:
        REQUEST_FILE.write_text(json.dumps(payload, indent=2))
    except OSError as exc:
        return False, f"не удалось записать запрос: {exc}"
    return True, "Запрос отправлен. Панель перезапустится через полминуты, клиенты переподключатся сами."


def run(stop_event: threading.Event) -> None:
    """Фоновая проверка раз в CHECK_INTERVAL_SECONDS. Первая — через минуту
    после старта, чтобы не мешать подъёму интерфейса."""
    if stop_event.wait(60):
        return
    while not stop_event.is_set():
        try:
            check()
        except Exception:
            pass
        stop_event.wait(CHECK_INTERVAL_SECONDS)
