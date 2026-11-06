"""
Обёртка над утилитами `awg` / `awg-quick` (пакет amneziawg-tools) для
применения конфигурации к реальному сетевому интерфейсу.

Работает по принципу "best effort": если утилиты не установлены (например,
при локальной разработке на Windows) — приложение продолжает работать в
режиме генерации конфигов, просто без применения на живую машину.

Требует root / CAP_NET_ADMIN на Linux-сервере.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .config import settings
from .fsutil import atomic_write

AWG_QUICK_BIN = shutil.which("awg-quick")
AWG_BIN = shutil.which("awg")
_PUBLIC_KEY_RE = re.compile(r"^\s*PublicKey\s*=\s*(\S+)", re.MULTILINE)


@dataclass
class CommandResult:
    ok: bool
    output: str
    code: int = 0


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
        return CommandResult(False, (result.stderr or result.stdout or "неизвестная ошибка").strip(),
                             result.returncode)
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
    atomic_write(path, content, 0o600)
    return path


def expected_peers(config_text: str) -> set[str]:
    """Публичные ключи пиров из конфига. В [Interface] ключ приватный, так
    что PublicKey встречается только у пиров."""
    return set(_PUBLIC_KEY_RE.findall(config_text))


def live_peers(interface_name: str) -> set[str] | None:
    """Пиры, которые реально стоят на интерфейсе. None: спросить не удалось."""
    result = _run([AWG_BIN, "show", interface_name, "peers"])
    return set(result.output.split()) if result.ok else None


def _syncconf(interface_name: str, path: Path) -> CommandResult:
    # Горячее применение: awg-quick strip убирает Address/MTU/PostUp/PostDown,
    # оставляя только то, что понимает `awg setconf`/`syncconf`.
    strip = subprocess.run([AWG_QUICK_BIN, "strip", str(path)], capture_output=True, text=True)
    if strip.returncode != 0:
        return CommandResult(False, strip.stderr.strip() or "awg-quick strip завершился с ошибкой")

    stripped_path = path.with_suffix(".stripped.conf")
    atomic_write(stripped_path, strip.stdout, 0o600)
    try:
        return _run([AWG_BIN, "syncconf", interface_name, str(stripped_path)])
    finally:
        stripped_path.unlink(missing_ok=True)


def _reconcile(interface_name: str, path: Path, config_text: str, result: CommandResult) -> CommandResult:
    """Сверить пиров на интерфейсе с конфигом и один раз повторить применение.

    syncconf может вернуть успех, а клиента на интерфейсе не окажется. Снаружи
    это выглядит как рабочая панель и клиент без связи, поэтому успехом
    считается только совпадение с ядром."""
    if not result.ok:
        return result
    expected = expected_peers(config_text)
    if live_peers(interface_name) == expected:
        return result

    print(f"[awg] {interface_name}: пиры расходятся с конфигом, повторяю применение")
    retry = _syncconf(interface_name, path)
    if not retry.ok:
        return retry
    live = live_peers(interface_name)
    if live == expected:
        return retry
    if live is None:
        return CommandResult(False, f"{interface_name}: не удалось получить список пиров")
    return CommandResult(False, f"{interface_name}: пиры не совпадают с конфигом: "
                                f"не хватает {len(expected - live)}, лишних {len(live - expected)}")


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
        result = _run([AWG_QUICK_BIN, "up", str(path)])
    else:
        result = _syncconf(interface_name, path)
    return _reconcile(interface_name, path, config_text, result)


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
    return _reconcile(interface_name, new_path, config_text, _run([AWG_QUICK_BIN, "up", str(new_path)]))


def down(interface_name: str) -> CommandResult:
    """Опустить интерфейс, который выключили в панели. Конфиг остаётся на
    диске: по нему и опускаем, а если его нет — просто удаляем линк."""
    if not tools_available():
        return CommandResult(False, "Утилиты awg/awg-quick не найдены в PATH")
    if not interface_is_up(interface_name):
        return CommandResult(True, "")
    path = _config_path(interface_name)
    if path.exists():
        result = _run([AWG_QUICK_BIN, "down", str(path)])
        if result.ok or not interface_is_up(interface_name):
            return CommandResult(True, result.output)
    return _run(["ip", "link", "delete", "dev", interface_name])


def run_rules(command: list[str]) -> CommandResult:
    """Запустить noisefloor-rules напрямую — когда набор интерфейсов или
    режим каскада поменялся, а основной интерфейс не перезапускался и его
    PostUp не срабатывал."""
    if not tools_available():
        return CommandResult(False, "Живое управление выключено")
    return _run(command)


def show_dump(interface_name: str) -> CommandResult:
    """Эквивалент `wg show <iface> dump` — машиночитаемый статус пиров."""
    if not AWG_BIN:
        return CommandResult(False, "Утилита awg не найдена в PATH")
    return _run([AWG_BIN, "show", interface_name, "dump"])
