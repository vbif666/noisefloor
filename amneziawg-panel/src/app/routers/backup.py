from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse

from .. import backup
from ..schemas import BackupInfo
from ..security import get_current_admin

router = APIRouter()


@router.get("", response_model=list[BackupInfo])
def list_backups(_admin: str = Depends(get_current_admin)):
    return backup.listing()


@router.post("", response_model=BackupInfo, status_code=status.HTTP_201_CREATED)
def create_backup(_admin: str = Depends(get_current_admin)):
    try:
        path = backup.create()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Не удалось создать копию: {exc}") from exc
    stat = path.stat()
    from datetime import datetime, timezone
    return BackupInfo(
        name=path.name,
        size=stat.st_size,
        created_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
        encrypted=path.name.endswith(".enc"),
    )


@router.get("/download")
def download_latest(_admin: str = Depends(get_current_admin)):
    """Отдаёт свежесобранную копию. Именно свежую, а не последнюю с диска:
    смысл кнопки — забрать актуальное состояние прямо сейчас."""
    try:
        path = backup.create()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Не удалось создать копию: {exc}") from exc
    return FileResponse(path, filename=path.name, media_type="application/octet-stream")
