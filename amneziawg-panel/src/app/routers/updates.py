from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from .. import awg_update, self_update
from ..schemas import SelfUpdateApply, UpdateApplyResponse, UpdateCheckResponse, UpdateComponent
from ..security import get_current_admin

router = APIRouter()


# --- Обновление самой панели -----------------------------------------------

@router.get("/self")
def self_update_status(_admin: str = Depends(get_current_admin)):
    """Что за версия стоит, что опубликовано, есть ли агент и чем кончилось
    прошлое обновление. Сеть не трогает — отдаёт последний результат
    фоновой проверки."""
    return self_update.status().as_dict()


@router.post("/self/check")
def self_update_check(_admin: str = Depends(get_current_admin)):
    return self_update.check().as_dict()


@router.post("/self/apply", response_model=SelfUpdateApply)
def self_update_apply(_admin: str = Depends(get_current_admin)):
    ok, message = self_update.request_update()
    if not ok:
        raise HTTPException(status_code=409, detail=message)
    return SelfUpdateApply(ok=True, message=message)


# --- Компоненты движка (только информация) ---------------------------------


@router.get("/check", response_model=UpdateCheckResponse)
def check_updates(_admin: str = Depends(get_current_admin)):
    result = awg_update.check_update()
    return UpdateCheckResponse(
        checked_ok=result.checked_ok,
        error=result.error,
        update_available=result.update_available,
        components=[
            UpdateComponent(
                name=c.name, current=c.current, latest=c.latest, update_available=c.update_available
            )
            for c in result.components
        ],
    )


@router.post("/apply", response_model=UpdateApplyResponse)
def apply_updates(_admin: str = Depends(get_current_admin)):
    ok, output = awg_update.run_update()
    return UpdateApplyResponse(ok=ok, output=output)
