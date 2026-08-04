"""Authentication endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import create_access_token, current_user, hash_password, verify_password
from app.database import get_db
from app.models import User
from app.schemas.auth import Token, UserCreate

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/setup", status_code=201)
def setup_first_admin(payload: UserCreate, db: Session = Depends(get_db)) -> dict:
    if db.scalar(select(func.count(User.id))):
        raise HTTPException(409, "Initial setup has already completed")
    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role="admin",
    )
    db.add(user)
    db.commit()
    return {"username": user.username, "role": user.role}


@router.post("/token", response_model=Token)
def token(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)) -> Token:
    user = db.scalar(select(User).where(User.username == form.username))
    if not user or not user.enabled or not verify_password(form.password, user.password_hash):
        raise HTTPException(401, "Invalid credentials")
    return Token(access_token=create_access_token(user.username))


@router.get("/me")
def me(user: User = Depends(current_user)) -> dict:
    return {"username": user.username, "email": user.email, "role": user.role}
