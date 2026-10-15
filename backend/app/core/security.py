"""Password hashing and JWT helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import Settings, get_settings

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False


def create_access_token(
    *,
    subject: str,
    roles: List[str],
    token_version: int,
    session_uid: Optional[str] = None,
    session_token_version: Optional[int] = None,
    settings: Optional[Settings] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    cfg = settings or get_settings()
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=cfg.access_token_expire_minutes)
    payload: Dict[str, Any] = {
        "sub": subject,
        "roles": roles,
        "tv": token_version,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "type": "access",
    }
    if session_uid is not None:
        payload["sid"] = session_uid
    if session_token_version is not None:
        payload["stv"] = session_token_version
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, cfg.secret_key, algorithm=cfg.jwt_algorithm)


def decode_access_token(token: str, settings: Optional[Settings] = None) -> Dict[str, Any]:
    cfg = settings or get_settings()
    try:
        payload = jwt.decode(token, cfg.secret_key, algorithms=[cfg.jwt_algorithm])
    except JWTError as exc:
        raise ValueError("Invalid or expired token") from exc
    if payload.get("type") != "access":
        raise ValueError("Invalid token type")
    if "sub" not in payload:
        raise ValueError("Token missing subject")
    return payload
