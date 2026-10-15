"""User registration and authentication service."""

from __future__ import annotations

from typing import List, Optional, Tuple

from sqlalchemy.orm import Session, joinedload

from app.core.security import hash_password, verify_password
from app.models.user import Role, User
from app.services.audit import write_audit

DEFAULT_ROLE = "user"


def get_or_create_role(db: Session, name: str, description: Optional[str] = None) -> Role:
    role = db.query(Role).filter(Role.name == name).first()
    if role is None:
        role = Role(name=name, description=description)
        db.add(role)
        db.flush()
    return role


def register_user(
    db: Session,
    *,
    email: str,
    password: str,
    full_name: str,
    role_names: Optional[List[str]] = None,
) -> User:
    existing = db.query(User).filter(User.email == email.lower()).first()
    if existing is not None:
        raise ValueError("Email already registered")

    roles_to_assign = role_names or [DEFAULT_ROLE]
    roles = [
        get_or_create_role(db, name=role_name, description=f"{role_name} role")
        for role_name in roles_to_assign
    ]

    user = User(
        email=email.lower().strip(),
        full_name=full_name.strip(),
        hashed_password=hash_password(password),
        is_active=True,
        token_version=0,
        roles=roles,
    )
    db.add(user)
    db.flush()
    write_audit(
        db,
        action="auth.register",
        outcome="success",
        actor_user_id=user.id,
        resource=user.email,
        detail="User registered",
    )
    db.commit()
    db.refresh(user)
    return (
        db.query(User)
        .options(joinedload(User.roles))
        .filter(User.id == user.id)
        .one()
    )


def authenticate_user(db: Session, *, email: str, password: str) -> Tuple[Optional[User], str]:
    user = (
        db.query(User)
        .options(joinedload(User.roles))
        .filter(User.email == email.lower().strip())
        .first()
    )
    if user is None or not verify_password(password, user.hashed_password):
        write_audit(
            db,
            action="auth.login",
            outcome="failure",
            resource=email.lower().strip(),
            detail="Invalid credentials",
        )
        db.commit()
        return None, "Invalid email or password"
    if not user.is_active:
        write_audit(
            db,
            action="auth.login",
            outcome="failure",
            actor_user_id=user.id,
            resource=user.email,
            detail="Inactive account",
        )
        db.commit()
        return None, "Account is inactive"
    write_audit(
        db,
        action="auth.login",
        outcome="success",
        actor_user_id=user.id,
        resource=user.email,
        detail="Login succeeded",
    )
    db.commit()
    return user, "ok"
