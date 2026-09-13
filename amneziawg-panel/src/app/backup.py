"""
Резервные копии каталога data.

Зачем: в data лежит всё, что невозможно восстановить — приватный ключ
сервера, приватные и preshared-ключи каждого клиента, секрет подписи
сессий, база. Один rm -rf, отказ диска или пересоздание VPS означали, что
каждый клиент заново сканирует QR-код. Копий не делал никто.

Что внутри архива: содержимое data без самих копий и без логов — логи
занимают место и восстанавливать их незачем.

Шифрование: если задан BACKUP_PASSPHRASE, архив шифруется AES-256 через
openssl. Это важно, потому что архив содержит все приватные ключи и его
обычно куда-то увозят — на почту, в облако, по HTTP без TLS.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from .config import DATA_DIR

BACKUP_DIR = DATA_DIR / "backups"
KEEP_BACKUPS = 14
BACKUP_INTERVAL_SECONDS = 24 * 3600

# Не кладём в архив: сами копии (рекурсия) и логи (объём без пользы).
EXCLUDE_NAMES = {"backups", "logs", "cascade-xray.log", "bin-backup"}

_lock = threading.Lock()


def _passphrase() -> str:
    return os.environ.get("BACKUP_PASSPHRASE", "").strip()


def _timestamp() -> str:
    # С точностью до секунды две копии, снятые подряд (по расписанию и
    # кнопкой), получали одно имя, и вторая молча затирала первую.
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")[:-3]


def create() -> Path:
    """Собирает архив и возвращает путь к нему. Потокобезопасно: две
    копии одновременно (по расписанию и по кнопке) не подерутся."""
    with _lock:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        encrypted = bool(_passphrase())
        suffix = ".tar.gz.enc" if encrypted else ".tar.gz"
        target = BACKUP_DIR / f"noisefloor-{_timestamp()}{suffix}"
        # Миллисекунд тоже бывает мало: на быстрой машине две копии подряд
        # укладываются в одну (поймано в CI). Имя обязано быть новым при
        # любых часах — досчитываем суффикс, пока не станет.
        counter = 1
        while target.exists():
            target = BACKUP_DIR / f"noisefloor-{_timestamp()}-{counter}{suffix}"
            counter += 1

        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            with tarfile.open(tmp_path, "w:gz") as tar:
                for item in sorted(DATA_DIR.iterdir()):
                    if item.name in EXCLUDE_NAMES:
                        continue
                    tar.add(item, arcname=item.name)

            if encrypted:
                result = subprocess.run(
                    ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-salt",
                     "-in", str(tmp_path), "-out", str(target),
                     "-pass", "env:BACKUP_PASSPHRASE"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if result.returncode != 0:
                    raise RuntimeError(f"не удалось зашифровать архив: {result.stderr.strip()}")
            else:
                shutil.move(str(tmp_path), target)
                tmp_path = None  # перемещён, удалять нечего
        finally:
            if tmp_path is not None and tmp_path.exists():
                tmp_path.unlink()

        target.chmod(0o600)
        _prune()
        return target


def _prune() -> None:
    copies = sorted(BACKUP_DIR.glob("noisefloor-*"), key=lambda p: p.stat().st_mtime, reverse=True)
    for stale in copies[KEEP_BACKUPS:]:
        try:
            stale.unlink()
        except OSError:
            pass


def listing() -> list[dict]:
    if not BACKUP_DIR.exists():
        return []
    items = []
    for path in sorted(BACKUP_DIR.glob("noisefloor-*"), key=lambda p: p.stat().st_mtime, reverse=True):
        stat = path.stat()
        items.append({
            "name": path.name,
            "size": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            "encrypted": path.name.endswith(".enc"),
        })
    return items


def latest() -> Path | None:
    copies = sorted(BACKUP_DIR.glob("noisefloor-*"), key=lambda p: p.stat().st_mtime, reverse=True) \
        if BACKUP_DIR.exists() else []
    return copies[0] if copies else None


def run(stop_event: threading.Event) -> None:
    """Копия при старте (чтобы она была хотя бы одна) и дальше раз в сутки."""
    made_initial = False
    last = 0.0
    while not stop_event.is_set():
        try:
            now = time.monotonic()
            if not made_initial or now - last >= BACKUP_INTERVAL_SECONDS:
                create()
                made_initial = True
                last = now
        except Exception:
            # Неудачная резервная копия не повод ронять панель — но и
            # молчать нельзя, поэтому пишем в лог контейнера.
            import traceback
            print("[backup] не удалось создать резервную копию:")
            traceback.print_exc()
        stop_event.wait(300)
