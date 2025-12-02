# app/auth/jwt.py
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Union
from uuid import UUID
import secrets

from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import hash_password, verify_password  # <-- Corrected
from app.auth.redis import add_to_blacklist, is_blacklisted
from app.schemas.token import TokenType
from app.database import get_db
from app.models.user import User

settings = get_settings()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


# --------------------- PASSWORD HELPERS ---------------------
def get_password_hash(password: str) -> str:
    """
    PUBLIC password hashing wrapper used by User model.
    """
    return hash_password(password)


def verify_user_password(plain: str, hashed: str) -> bool:
    """
    PUBLIC password verification wrapper used by User model.
    """
    return verify_password(plain, hashed)


# --------------------- JWT CREATION ---------------------
def create_token(
    user_id: Union[str, UUID],
    token_type: TokenType,
    expires_delta: Optional[timedelta] = None
) -> str:

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        if token_type == TokenType.ACCESS:
            expire = datetime.now(timezone.utc) + timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                days=settings.REFRESH_TOKEN_EXPIRE_DAYS
            )

    if isinstance(user_id, UUID):
        user_id = str(user_id)

    payload = {
        "sub": user_id,
        "type": token_type.value,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": secrets.token_hex(16)
    }

    secret = (
        settings.JWT_SECRET_KEY
        if token_type == TokenType.ACCESS
        else settings.JWT_REFRESH_SECRET_KEY
    )

    try:
        return jwt.encode(payload, secret, algorithm=settings.ALGORITHM)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not create token: {e}"
        )


# --------------------- JWT DECODING ---------------------
async def decode_token(
    token: str,
    token_type: TokenType,
    verify_exp: bool = True
) -> dict[str, Any]:

    secret = (
        settings.JWT_SECRET_KEY
        if token_type == TokenType.ACCESS
        else settings.JWT_REFRESH_SECRET_KEY
    )

    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=[settings.ALGORITHM],
            options={"verify_exp": verify_exp}
        )

        # Wrong token type (access token used where refresh expected, etc)
        if payload.get("type") != token_type.value:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Check blacklist
        if await is_blacklisted(payload["jti"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return payload

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# --------------------- CURRENT USER DEPENDENCY ---------------------
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """
    Extracts the user from an access token.
    """

    payload = await decode_token(token, TokenType.ACCESS)
    user_id = payload["sub"]

    user = db.query(User).filter(User.id == user_id).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User inactive"
        )

    return user
