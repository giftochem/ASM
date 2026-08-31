from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    """Bootstraps a brand new tenant: creates an Organization plus its first
    (admin) User in one call. There is no other way to create the first
    admin, since every other user-creation path requires an existing admin.
    Every subsequent user in that organization is created via POST /users
    by an admin, not through this endpoint.
    """

    organization_name: str = Field(min_length=1, max_length=255)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    full_name: str = Field(min_length=1, max_length=255)
