"""
Запись файлов, которые нельзя увидеть наполовину.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    """Заменить файл целиком: читатель видит либо старую версию, либо новую.

    Временный файл лежит в том же каталоге, иначе os.replace перестаёт быть
    атомарным. Сбой питания посреди записи не оставит обрезанный конфиг.
    Права ставятся до появления файла под настоящим именем: в нём приватные
    ключи."""
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise

    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
