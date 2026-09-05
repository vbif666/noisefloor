from __future__ import annotations

from fastapi import APIRouter, Depends

from .. import awg_update
from ..schemas import UpdateApplyResponse, UpdateCheckResponse, UpdateComponent
from ..security import get_current_admin

router = APIRouter()


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
