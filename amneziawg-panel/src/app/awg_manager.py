"""
Обёртка над утилитами `awg` / `awg-quick` (пакет amneziawg-tools) для
применения конфигурации к реальному сетевому интерфейсу.

Работает по принципу "best effort": если утилиты не установлены (например,
при локальной разработке на Windows) — приложение продолжает работать в
режиме генерации конфигов, просто без применения на живую машину.

Требует root / CAP_NET_ADMIN на Linux-сервере.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .config import settings

AWG_QUICK_BIN = shutil.which("awg-quick")
AWG_BIN = shutil.which("awg")


@dataclass
class CommandResult:
    ok: bool
    output: str


def tools_available() -> bool:
    return bool(AWG_QUICK_BIN and AWG_BIN) and settings.live_management_enabled


def _config_path(interface_name: str) -> Path:
    return Path(settings.awg_config_dir) / f"{interface_name}.conf"


def _run(cmd: list[str]) -> CommandResult:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except FileNotFoundError as exc:
        return CommandResult(False, str(exc))
    except subprocess.TimeoutExpired:
        return CommandResult(False, f"Команда не ответила за 30с: {' '.join(cmd)}")
    if result.returncode != 0:
        return CommandResult(False, (result.stderr or result.stdout or "неизвестная ошибка").strip())
    return CommandResult(True, result.stdout.strip())


def interface_is_up(interface_name: str) -> bool:
    result = subprocess.run(["ip", "link", "show", interface_name], capture_output=True, text=True)
    return result.returncode == 0


def interface_mtu(interface_name: str) -> int | None:
    """Фактический MTU интерфейса прямо с хоста — то, что реально применилось,
    а не то, что записано в БД/конфиге (эти два значения могут разойтись,
    например если apply/restart не выполнялся после правки)."""
    try:
        return int(Path(f"/sys/class/net/{interface_name}/mtu").read_text().strip())
    except (OSError, ValueError):
        return None


def write_config_file(interface_name: str, content: str) -> Path:
    path = _config_path(interface_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    # 0600: файл содержит приватные ключи всех клиентов
    path.write_text(content)
    path.chmod(0o600)
    return path


def apply(interface_name: str, config_text: str) -> CommandResult:
    """
    Применяет конфиг на живой интерфейс без разрыва существующих туннелей,
    если это возможно (awg syncconf), либо поднимает интерфейс с нуля,
    если он ещё не запущен.
    """
    if not tools_available():
        return CommandResult(False, "Утилиты awg/awg-quick не найдены в PATH — доступна только генерация конфигов")

    path = write_config_file(interface_name, config_text)

    if not interface_is_up(interface_name):
        return _run([AWG_QUICK_BIN, "up", str(path)])

    # Горячее применение: awg-quick strip убирает Address/MTU/PostUp/PostDown,
    # оставляя только то, что понимает `awg setconf`/`syncconf`.
    strip = subprocess.run([AWG_QUICK_BIN, "strip", str(path)], capture_output=True, text=True)
    if strip.returncode != 0:
        return CommandResult(False, strip.stderr.strip() or "awg-quick strip завершился с ошибкой")

    stripped_path = path.with_suffix(".stripped.conf")
    stripped_path.write_text(strip.stdout)
    stripped_path.chmod(0o600)
    try:
        return _run([AWG_BIN, "syncconf", interface_name, str(stripped_path)])
    finally:
        stripped_path.unlink(missing_ok=True)


def restart(interface_name: str, config_text: str) -> CommandResult:
    """Полный перезапуск интерфейса (down + up) — на случай, если горячий sync не подхватил что-то."""
    if not tools_available():
        return CommandResult(False, "Утилиты awg/awg-quick не найдены в PATH")
    path = _config_path(interface_name)
    if interface_is_up(interface_name) and path.exists():
        # down должен выполняться по ФАЙЛУ, КОТОРЫЙ СЕЙЧАС ЖИВОЙ на интерфейсе,
        # а не по новому конфиге — иначе PostDown новых правил (например,
        # только что добавленного TCPMSS clamp) пытается -D то, что старый
        # PostUp никогда не -A'л, awg-quick down падает с ошибкой и restart()
        # прерывается ДО up, оставляя интерфейс лежать (было 2026-07-15).
        down = _run([AWG_QUICK_BIN, "down", str(path)])
        if not down.ok:
            return down
    new_path = write_config_file(interface_name, config_text)
    return _run([AWG_QUICK_BIN, "up", str(new_path)])


def show_dump(interface_name: str) -> CommandResult:
    """Эквивалент `wg show <iface> dump` — машиночитаемый статус пиров."""
    if not AWG_BIN:
        return CommandResult(False, "Утилита awg не найдена в PATH")
    return _run([AWG_BIN, "show", interface_name, "dump"])
