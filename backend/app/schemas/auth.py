"""Auth request/response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=1, max_length=255)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    # Optional device context captured at login for continuous monitoring demos.
    device_id: Optional[str] = Field(default=None, max_length=128)
    device_trusted: bool = False
    context_label: Optional[str] = Field(default=None, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    session_uid: Optional[str] = None
    expires_in_minutes: int


class UserResponse(BaseModel):
    id: int
    email: EmailStr
    full_name: str
    is_active: bool
    roles: List[str]
    created_at: datetime

    model_config = {"from_attributes": True}
