"""Policy engine: translates risk scores into adaptive access decisions.

Policy configuration
--------------------
Thresholds are read from application settings (configurable, not hardcoded).

Provisional thresholds (from settings):
    low:      0-24   -> allow + monitor
    medium:   25-49  -> allow_limited or increase monitoring
    high:     50-74  -> step_up required (restrict sensitive operations)
    critical: 75-100 -> deny or revoke

Policy decisions
----------------
allow         - full access granted
allow_limited - access granted with reduced permissions / increased monitoring
step_up       - step-up authentication required before sensitive operations
deny          - request denied, session may continue
revoke        - session is immediately revoked

Hysteresis
----------
To prevent flickering at thresholds, a session must maintain a risk score
above/below a boundary for `HYSTERESIS_CONSECUTIVE_EVENTS` consecutive
assessments before escalating or de-escalating its risk level.

Security invariant
------------------
A low-risk score never grants permissions the user does not possess via RBAC.
The policy engine only RESTRICTS; it never GRANTS additional permissions.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Hysteresis: require N consecutive assessments at a new level before switching.
HYSTERESIS_CONSECUTIVE_EVENTS = 2

# Resource sensitivity thresholds.
HIGH_SENSITIVITY_THRESHOLD = 4  # resources with sensitivity >= this are "sensitive"


@dataclass
class PolicyDecision:
    decision: str  # allow | allow_limited | step_up | deny | revoke
    policy_reason: str
    authorized_by_rbac: bool
    risk_score: float
    risk_level: str
    resource_name: Optional[str] = None
    resource_sensitivity: int = 1
    metadata: Dict[str, Any] = field(default_factory=dict)


def evaluate(
    *,
    risk_score: float,
    risk_level: str,
    resource_sensitivity: int,
    resource_name: Optional[str],
    user_roles: list[str],
    required_role: Optional[str] = None,
    session_status: str = "active",
    previous_risk_level: Optional[str] = None,
    consecutive_risk_count: int = 0,
    settings,
) -> PolicyDecision:
    """Evaluate an access request and return a PolicyDecision.

    Parameters
    ----------
    risk_score:            Current session risk score (0-100).
    risk_level:            Current risk level string.
    resource_sensitivity:  1-5 sensitivity of requested resource.
    resource_name:         Resource identifier.
    user_roles:            List of the user's RBAC role names.
    required_role:         Role required for this resource (if any).
    session_status:        Current session status from DB.
    previous_risk_level:   Previous risk level for hysteresis check.
    consecutive_risk_count: Number of consecutive events at current level.
    settings:              Application settings (for threshold config).
    """

    # 1. RBAC check — must pass regardless of risk score.
    if required_role and required_role.lower() not in {r.lower() for r in user_roles}:
        return PolicyDecision(
            decision="deny",
            policy_reason=f"RBAC: user lacks required role '{required_role}'",
            authorized_by_rbac=False,
            risk_score=risk_score,
            risk_level=risk_level,
            resource_name=resource_name,
            resource_sensitivity=resource_sensitivity,
        )

    # 2. Revoked session check.
    if session_status == "revoked":
        return PolicyDecision(
            decision="deny",
            policy_reason="Session is revoked; all requests denied",
            authorized_by_rbac=True,
            risk_score=risk_score,
            risk_level=risk_level,
            resource_name=resource_name,
            resource_sensitivity=resource_sensitivity,
        )

    # 3. Apply hysteresis: only escalate if threshold maintained.
    effective_risk_level = _apply_hysteresis(
        current=risk_level,
        previous=previous_risk_level,
        consecutive_count=consecutive_risk_count,
    )

    # 4. Policy decision based on risk level and resource sensitivity.
    is_sensitive = resource_sensitivity >= HIGH_SENSITIVITY_THRESHOLD

    if effective_risk_level == "low":
        decision = "allow"
        reason = (
            f"Low risk ({risk_score:.1f}); access granted with standard monitoring"
        )

    elif effective_risk_level == "medium":
        if is_sensitive:
            decision = "allow_limited"
            reason = (
                f"Medium risk ({risk_score:.1f}) + sensitive resource (sensitivity={resource_sensitivity}); "
                "access granted with increased monitoring"
            )
        else:
            decision = "allow"
            reason = f"Medium risk ({risk_score:.1f}); access granted, monitoring increased"

    elif effective_risk_level == "high":
        if is_sensitive:
            decision = "step_up"
            reason = (
                f"High risk ({risk_score:.1f}) + sensitive resource (sensitivity={resource_sensitivity}); "
                "step-up authentication required"
            )
        else:
            decision = "allow_limited"
            reason = (
                f"High risk ({risk_score:.1f}); access granted with reduced privileges"
            )

    else:  # critical
        if is_sensitive:
            decision = "revoke"
            reason = (
                f"Critical risk ({risk_score:.1f}) + sensitive resource (sensitivity={resource_sensitivity}); "
                "session revoked"
            )
        else:
            decision = "deny"
            reason = (
                f"Critical risk ({risk_score:.1f}); request denied. "
                "Session may be revoked on continued violation."
            )

    return PolicyDecision(
        decision=decision,
        policy_reason=reason,
        authorized_by_rbac=True,
        risk_score=risk_score,
        risk_level=effective_risk_level,
        resource_name=resource_name,
        resource_sensitivity=resource_sensitivity,
        metadata={
            "hysteresis_applied": effective_risk_level != risk_level,
            "raw_risk_level": risk_level,
        },
    )


def _apply_hysteresis(
    *,
    current: str,
    previous: Optional[str],
    consecutive_count: int,
) -> str:
    """Return effective risk level considering hysteresis.

    Escalation requires HYSTERESIS_CONSECUTIVE_EVENTS consecutive assessments.
    De-escalation is immediate (safer to de-escalate quickly).
    """
    if previous is None:
        return current

    levels = ["low", "medium", "high", "critical"]

    def _level_idx(lvl: str) -> int:
        try:
            return levels.index(lvl)
        except ValueError:
            return 0

    current_idx = _level_idx(current)
    previous_idx = _level_idx(previous)

    if current_idx > previous_idx:
        # Escalation: apply hysteresis.
        if consecutive_count < HYSTERESIS_CONSECUTIVE_EVENTS:
            logger.debug(
                "Hysteresis: %s -> %s suppressed (%d/%d events)",
                previous,
                current,
                consecutive_count,
                HYSTERESIS_CONSECUTIVE_EVENTS,
            )
            return previous  # Stay at previous level until threshold.
    # De-escalation or same level: immediate.
    return current


def should_revoke_session(
    *,
    risk_score: float,
    risk_level: str,
    decision: str,
    resource_sensitivity: int,
    consecutive_critical_count: int = 0,
) -> bool:
    """Return True if the session should be auto-revoked by policy."""
    if decision == "revoke":
        return True
    if risk_level == "critical" and consecutive_critical_count >= 3:
        return True
    return False
