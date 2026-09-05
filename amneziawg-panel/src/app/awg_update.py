"""
Проверка и установка обновлений amneziawg-go / amneziawg-tools из ОФИЦИАЛЬНЫХ
репозиториев amnezia-vpn (см. Dockerfile - там они и собираются при билде
образа). Даёт панели проверить наличие новых git-тегов и запустить сборку
по кнопке из UI, а не только ждать фоновый цикл update-awg-tools.sh
(интервал AWG_AUTO_UPDATE_INTERVAL_HOURS, по умолчанию раз в сутки).

Фактическую сборку выполняет тот же update-awg-tools.sh (git clone + make),
чтобы не дублировать логику в двух местах.
"""
from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from .config import DATA_DIR

REPO_GO = "amnezia-vpn/amneziawg-go"
REPO_TOOLS = "amnezia-vpn/amneziawg-tools"
UPDATE_SCRIPT = Path("/usr/local/bin/update-awg-tools.sh")
VERSION_FILE = DATA_DIR / "awg-versions.txt"


@dataclass
class ComponentUpdate:
    name: str
    current: str | None
    latest: str | None
    update_available: bool


@dataclass
class UpdateCheckResult:
    checked_ok: bool
    error: str | None
    components: list[ComponentUpdate] = field(default_factory=list)

    @property
    def update_available(self) -> bool:
        return any(c.update_available for c in self.components)


def _gh_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "amneziawg-panel"}
    token = os.environ.get("AWG_UPDATE_GITHUB_PAT", "")
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def _latest_tag(repo: str) -> str | None:
    """Самый свежий git-тег репозитория (GitHub отдаёт их от новых к старым)."""
    url = f"https://api.github.com/repos/{repo}/tags?per_page=1"
    req = urllib.request.Request(url, headers=_gh_headers())
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.load(resp)
        return data[0]["name"] if data else None
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError, IndexError):
        return None


def _installed_version(name: str) -> str | None:
    """Версия, реально стоящая в бинарнике: сначала файл, который пишет
    update-awg-tools.sh после успешной пересборки, если его ещё нет
    (свежий контейнер, обновлений ещё не было) - тег, из которого собран
    образ (задан в Dockerfile через ENV AWG_*_BUILT_REF)."""
    if VERSION_FILE.exists():
        for line in VERSION_FILE.read_text().splitlines():
            if line.startswith(f"{name}="):
                value = line.split("=", 1)[1].strip()
                if value:
                    return value
    env_name = "AWG_GO_BUILT_REF" if name == "amneziawg-go" else "AWG_TOOLS_BUILT_REF"
    return os.environ.get(env_name) or None


def check_update() -> UpdateCheckResult:
    go_latest = _latest_tag(REPO_GO)
    tools_latest = _latest_tag(REPO_TOOLS)

    if go_latest is None and tools_latest is None:
        return UpdateCheckResult(
            checked_ok=False,
            error="Не удалось обратиться к GitHub API (нет сети или сработал rate-limit)",
        )

    go_current = _installed_version("amneziawg-go")
    tools_current = _installed_version("amneziawg-tools")

    return UpdateCheckResult(
        checked_ok=True,
        error=None,
        components=[
            ComponentUpdate(
                name="amneziawg-go",
                current=go_current,
                latest=go_latest,
                update_available=bool(go_latest and go_latest != go_current),
            ),
            ComponentUpdate(
                name="amneziawg-tools",
                current=tools_current,
                latest=tools_latest,
                update_available=bool(tools_latest and tools_latest != tools_current),
            ),
        ],
    )


def run_update() -> tuple[bool, str]:
    """Однократный запуск update-awg-tools.sh: пересобирает из официальных
    исходников то, что устарело, и переприменяет конфиг. Блокирующий вызов -
    сборка Go + C обычно укладывается в 1-2 минуты, поэтому таймаут щедрый."""
    if not UPDATE_SCRIPT.exists():
        # Штатная ситуация начиная со сборки, где тулчейн убран из рантайма:
        # версии закреплены при сборке образа, обновление приезжает новым
        # образом. Это сообщение читает администратор в интерфейсе, поэтому
        # оно говорит, что делать, а не только что пошло не так.
        return False, (
            "Этот образ не собирает бинарники на лету — версии закреплены при сборке. "
            "Чтобы обновиться: docker compose pull && docker compose up -d"
        )
    try:
        result = subprocess.run(
            ["/bin/sh", str(UPDATE_SCRIPT)],
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        return False, "Обновление не уложилось в 10 минут - проверьте `docker logs`"
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    return result.returncode == 0, output
