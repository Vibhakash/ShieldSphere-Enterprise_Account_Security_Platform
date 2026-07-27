from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID
from pydantic import BaseModel, EmailStr, field_validator
import re


class UserRegister(BaseModel):
    email: EmailStr
    username: str
    password: str
    full_name: Optional[str] = None

    @field_validator("username")
    @classmethod
    def username_valid(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_]{3,30}$", v):
            raise ValueError("Username must be 3-30 chars, alphanumeric/underscore only")
        return v

    @field_validator("password")
    @classmethod
    def password_strong(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str
    device_fingerprint: Optional[str] = None
    user_agent: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    requires_2fa: bool = False
    user_id: Optional[str] = None


class RefreshRequest(BaseModel):
    refresh_token: Optional[str] = None


class TwoFactorVerify(BaseModel):
    code: str
    temp_token: str  # short-lived token issued after password-only login


class TwoFactorSetupResponse(BaseModel):
    secret: str
    qr_uri: str
    qr_data_url: str  # base64 PNG for frontend display


class TwoFactorConfirm(BaseModel):
    code: str


class ChangePassword(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def strong_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("New password must be at least 8 characters")
        return v


class UserOut(BaseModel):
    id: UUID
    email: str
    username: str
    full_name: Optional[str]
    role: str
    totp_enabled: bool
    is_active: bool
    password_breached: bool
    password_breach_count: int
    created_at: datetime
    last_login_at: Optional[datetime]

    model_config = {"from_attributes": True}


class PasskeyRegistrationVerify(BaseModel):
    ceremony_id: str
    name: str
    credential: Dict[str, Any]

    @field_validator("name")
    @classmethod
    def valid_passkey_name(cls, value: str) -> str:
        value = value.strip()
        if not 1 <= len(value) <= 100:
            raise ValueError("Passkey name must be between 1 and 100 characters")
        return value


class PasskeyLoginVerify(BaseModel):
    ceremony_id: str
    credential: Dict[str, Any]
    device_fingerprint: Optional[str] = None
