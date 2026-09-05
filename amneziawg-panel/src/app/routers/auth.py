from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import security
from ..database import get_db
from ..models import AdminUser
from ..schemas import LoginRequest, MeResponse, TokenResponse

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    rate_key = payload.username.strip().lower()
    security.check_login_rate_limit(rate_key)

    user = db.query(AdminUser).filter(AdminUser.username == payload.username).first()
    if not user or not security.verify_password(payload.password, user.password_hash):
        security.register_failed_login(rate_key)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Неверный логин или пароль")

    security.register_successful_login(rate_key)
    token = security.create_access_token(user.username)
    return TokenResponse(access_token=token)


@router.get("/me", response_model=MeResponse)
def me(username: str = Depends(security.get_current_admin)):
    return MeResponse(username=username)
