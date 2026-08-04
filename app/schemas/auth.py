from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    role: str = Field(default="analyst", pattern=r"^(admin|analyst|viewer)$")


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
