# app/core/security.py

from passlib.context import CryptContext

# Central password hashing configuration.
# Using pbkdf2_sha256 avoids the bcrypt backend issues and has no extra deps.
pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto",
)


def hash_password(password: str) -> str:
    """Hash a plaintext password."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against its hashed version."""
    return pwd_context.verify(plain_password, hashed_password)
