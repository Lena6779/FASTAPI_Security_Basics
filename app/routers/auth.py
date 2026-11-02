"""
Auth router.

Security features:
- Rate limiting: /login allows 5 attempts per minute per IP to slow down
  password guessing.
- Input limits: email and password have length bounds, so oversized values are
  rejected before any password hashing happens.
- Passwords are hashed and compared in constant time, and the error message
  doesn't reveal whether the email or the password was wrong.

NOTE: This is a demo login for the rate limiting exercise. It checks one demo
user and does not issue a session or token.
"""

import hashlib
import hmac
import os
import secrets

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from app.limiter import LOGIN_LIMIT, limiter

router = APIRouter(tags=["auth"])

DEMO_EMAIL = os.getenv("DEMO_EMAIL", "demo@example.com")
PASSWORD_SALT = secrets.token_bytes(16)


def hash_password(password: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), PASSWORD_SALT, 100_000)


# Never store a plain text password. Set DEMO_PASSWORD to override the default.
DEMO_PASSWORD_HASH = hash_password(os.getenv("DEMO_PASSWORD", "demo-password"))


class LoginRequest(BaseModel):
    email: str = Field(
        ...,
        min_length=3,
        max_length=254,  # the longest valid email address
        pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
    )
    password: str = Field(..., min_length=8, max_length=128)


@router.post("/login")
@limiter.limit(LOGIN_LIMIT)
def login(request: Request, response: Response, credentials: LoginRequest):
    # request and response are required by SlowAPI to count the call and add headers
    # compare_digest only accepts non-ASCII text as bytes, so encode the emails first
    email_matches = hmac.compare_digest(
        credentials.email.encode(), DEMO_EMAIL.encode()
    )
    password_matches = hmac.compare_digest(
        hash_password(credentials.password), DEMO_PASSWORD_HASH
    )

    if not (email_matches and password_matches):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    return {"message": "Login successful"}
