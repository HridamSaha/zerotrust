"""Append-oriented audit log helper."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.models.audit import AuditLog


def write_audit(
    db: Session,
    *,
    action: str,
    outcome: str,
    actor_user_id: Optional[int] = None,
    session_id: Optional[int] = None,
    resource: Optional[str] = None,
    detail: Optional[str] = None,
    evidence: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    entry = AuditLog(
        actor_user_id=actor_user_id,
        session_id=session_id,
        action=action,
        resource=resource,
        outcome=outcome,
        detail=detail,
        evidence=evidence,
    )
    db.add(entry)
    return entry


def log_event(
    db: Session,
    *,
    user_id: Optional[int] = None,
    session_id: Optional[int] = None,
    action: str,
    resource: Optional[str] = None,
    outcome: str,
    detail: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    """Convenience wrapper used by the risk assessment service."""
    detail_str = json.dumps(detail, default=str) if detail else None
    return write_audit(
        db,
        action=action,
        outcome=outcome,
        actor_user_id=user_id,
        session_id=session_id,
        resource=resource,
        detail=detail_str,
        evidence=detail,
    )
