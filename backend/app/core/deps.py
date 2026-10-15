"""FastAPI authentication and authorization dependencies."""

from __future__ import annotations

from typing import Annotated, List, Optional

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session, joinedload

from app.config import Settings, get_settings
from app.core.rate_limit import auth_rate_limiter
from app.core.security import decode_access_token
from app.database import get_db
from app.models.session import UserSession
from app.models.user import User

bearer_scheme = HTTPBearer(auto_error=False)


def enforce_auth_rate_limit(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    client_host = request.client.host if request.client else "unknown"
    key = f"auth:{client_host}"
    allowed = auth_rate_limiter.allow(
        key,
        limit=settings.auth_rate_limit_requests,
        window_seconds=settings.auth_rate_limit_window_seconds,
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many authentication attempts. Try again later.",
        )


def get_current_user(
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> User:
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_access_token(credentials.credentials, settings=settings)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    try:
        user_id = int(payload["sub"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token subject",
        ) from exc

    user = (
        db.query(User)
        .options(joinedload(User.roles))
        .filter(User.id == user_id)
        .first()
    )
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    token_version = int(payload.get("tv", -1))
    if token_version != user.token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
        )

    # Stash decoded claims for downstream session checks.
    user._token_claims = payload  # type: ignore[attr-defined]
    return user


def get_optional_session(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    x_session_id: Annotated[Optional[str], Header(alias="X-Session-Id")] = None,
) -> Optional[UserSession]:
    """Resolve session from JWT claim or X-Session-Id header."""
    claims = getattr(current_user, "_token_claims", {}) or {}
    session_uid = x_session_id or claims.get("sid")
    if not session_uid:
        return None

    session = (
        db.query(UserSession)
        .filter(
            UserSession.session_uid == session_uid,
            UserSession.user_id == current_user.id,
        )
        .first()
    )
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    claim_stv = claims.get("stv")
    if claim_stv is not None and int(claim_stv) != session.session_token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session token has been revoked",
        )
    return session


def require_active_session(
    session: Annotated[Optional[UserSession], Depends(get_optional_session)],
) -> UserSession:
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Active session required (create one via POST /api/sessions)",
        )
    if session.status == "revoked":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session has been revoked",
        )
    return session


def require_roles(*allowed_roles: str):
    allowed = {role.lower() for role in allowed_roles}

    def _dependency(current_user: Annotated[User, Depends(get_current_user)]) -> User:
        user_roles = {role.name.lower() for role in current_user.roles}
        if not user_roles.intersection(allowed):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {sorted(allowed)}",
            )
        return current_user

    return _dependency


def user_role_names(user: User) -> List[str]:
    return sorted({role.name for role in user.roles})
