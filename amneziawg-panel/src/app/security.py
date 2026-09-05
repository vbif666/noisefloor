import time
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import settings

_bearer_scheme = HTTPBearer(auto_error=False)

ALGORITHM = "HS256"

# --- Простая защита логина от перебора пароля ---
# Панель однопроцессная (uvicorn без --workers), так что состояние в памяти
# процесса корректно и не требует внешнего хранилища (Redis и т.п.).
_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW_SECONDS = 300  # 5 минут
_LOGIN_LOCKOUT_SECONDS = 300
_failed_logins: dict[str, list[float]] = {}
_locked_until: dict[str, float] = {}


def check_login_rate_limit(key: str) -> None:
    """key — обычно username, приведённый к нижнему регистру, либо IP."""
    now = time.monotonic()
    until = _locked_until.get(key)
    if until and now < until:
        retry_after = int(until - now)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Слишком много неудачных попыток входа, повторите через {retry_after} с",
            headers={"Retry-After": str(retry_after)},
        )


def register_failed_login(key: str) -> None:
    now = time.monotonic()
    attempts = [t for t in _failed_logins.get(key, []) if now - t < _LOGIN_WINDOW_SECONDS]
    attempts.append(now)
    _failed_logins[key] = attempts
    if len(attempts) >= _LOGIN_MAX_ATTEMPTS:
        _locked_until[key] = now + _LOGIN_LOCKOUT_SECONDS
        _failed_logins[key] = []


def register_successful_login(key: str) -> None:
    _failed_logins.pop(key, None)
    _locked_until.pop(key, None)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def create_access_token(username: str) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {"sub": username, "exp": expires_at}
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def decode_access_token(token: str) -> str:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Сессия недействительна или истекла, войдите заново",
        ) from exc
    return payload["sub"]


def get_current_admin(creds: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme)) -> str:
    if creds is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Требуется авторизация")
    return decode_access_token(creds.credentials)
