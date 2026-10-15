"""Authentication routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.core.deps import enforce_auth_rate_limit, get_current_user, user_role_names
from app.core.security import create_access_token
from app.database import get_db
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserResponse
from app.services.auth_service import authenticate_user, register_user
from app.services.session_service import create_session

router = APIRouter(prefix="/auth", tags=["auth"])


def _to_user_response(user) -> UserResponse:
    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        roles=user_role_names(user),
        created_at=user.created_at,
    )


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_auth_rate_limit)],
)
def register(
    body: RegisterRequest,
    db: Annotated[Session, Depends(get_db)],
) -> UserResponse:
    try:
        user = register_user(
            db,
            email=str(body.email),
            password=body.password,
            full_name=body.full_name,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return _to_user_response(user)


@router.post(
    "/login",
    response_model=TokenResponse,
    dependencies=[Depends(enforce_auth_rate_limit)],
)
def login(
    body: LoginRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> TokenResponse:
    user, message = authenticate_user(db, email=str(body.email), password=body.password)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=message)

    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    session = create_session(
        db,
        user=user,
        device_id=body.device_id,
        device_trusted=body.device_trusted,
        client_ip=client_ip,
        user_agent=user_agent,
        context_label=body.context_label,
    )

    token = create_access_token(
        subject=str(user.id),
        roles=user_role_names(user),
        token_version=user.token_version,
        session_uid=session.session_uid,
        session_token_version=session.session_token_version,
        settings=settings,
    )
    return TokenResponse(
        access_token=token,
        session_uid=session.session_uid,
        expires_in_minutes=settings.access_token_expire_minutes,
    )


@router.get("/me", response_model=UserResponse)
def me(current_user=Depends(get_current_user)) -> UserResponse:
    return _to_user_response(current_user)
