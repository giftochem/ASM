import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.core.enums import UserRole


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    full_name: str = Field(min_length=1, max_length=255)
    role: UserRole = UserRole.viewer


class UserUpdate(BaseModel):
    """Admin-only. Both fields optional so a caller can change just one;
    at least one must be provided (enforced in the route, not here, since
    "at least one of these" isn't cleanly expressible as a field-level
    Pydantic constraint).
    """

    role: UserRole | None = None
    is_active: bool | None = None


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    email: EmailStr
    full_name: str
    role: UserRole
    is_active: bool
    created_at: datetime
