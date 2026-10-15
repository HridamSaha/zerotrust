"""Development seed data: roles and demo accounts."""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.config import Settings
from app.core.security import hash_password
from app.models.user import Role, User
from app.services.auth_service import get_or_create_role

logger = logging.getLogger(__name__)

ROLE_DEFINITIONS = [
    ("admin", "Full administrative access"),
    ("analyst", "Security analyst — read sessions, risk, audit"),
    ("user", "Standard authenticated user"),
]


def seed_roles(db: Session) -> None:
    for name, description in ROLE_DEFINITIONS:
        get_or_create_role(db, name=name, description=description)
    db.commit()


def _ensure_demo_user(
    db: Session,
    *,
    email: str,
    password: str,
    full_name: str,
    role_name: str,
) -> User:
    user = db.query(User).filter(User.email == email.lower()).first()
    role = db.query(Role).filter(Role.name == role_name).one()
    if user is None:
        user = User(
            email=email.lower(),
            full_name=full_name,
            hashed_password=hash_password(password),
            is_active=True,
            token_version=0,
            roles=[role],
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info("Seeded demo account %s with role %s", email, role_name)
        return user

    # Keep role assignment idempotent without resetting passwords on every boot.
    if role not in user.roles:
        user.roles.append(role)
        db.commit()
        db.refresh(user)
    return user


def seed_demo_accounts(db: Session, settings: Settings) -> None:
    if not settings.is_development:
        logger.info("Skipping demo account seed outside development")
        return

    seed_roles(db)
    _ensure_demo_user(
        db,
        email=settings.demo_admin_email,
        password=settings.demo_admin_password,
        full_name="Demo Admin",
        role_name="admin",
    )
    _ensure_demo_user(
        db,
        email=settings.demo_user_email,
        password=settings.demo_user_password,
        full_name="Demo User",
        role_name="user",
    )
