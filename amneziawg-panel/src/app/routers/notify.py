from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from .. import notify
from ..schemas import NotifySettings, NotifyUpdate
from ..security import get_current_admin

router = APIRouter()


@router.get("", response_model=NotifySettings)
def get_settings(_admin: str = Depends(get_current_admin)):
    return notify.public_settings()


@router.put("", response_model=NotifySettings)
def put_settings(body: NotifyUpdate, _admin: str = Depends(get_current_admin)):
    webhook = body.webhook_url.strip()
    if webhook and not notify.valid_url(webhook):
        raise HTTPException(status_code=422, detail="Адрес webhook должен начинаться с http:// или https://")
    config = notify.load_config()
    config.update(webhook_url=webhook, telegram_chat_id=body.telegram_chat_id.strip())
    if body.telegram_token is not None:
        config["telegram_token"] = body.telegram_token.strip()
    notify.save_config(config)
    return notify.public_settings()


@router.post("/test", response_model=NotifySettings)
def send_test(_admin: str = Depends(get_current_admin)):
    error = notify.send_test()
    if error:
        raise HTTPException(status_code=502, detail=f"Сообщение не доставлено: {error}")
    return notify.public_settings()
