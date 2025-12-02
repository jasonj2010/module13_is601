# app/auth/redis.py

from __future__ import annotations

import time
from typing import Optional

from app.core.config import settings

# Try to import aioredis, but don't crash the app if it fails
try:
    import aioredis  # type: ignore
except Exception:  # noqa: BLE001 - broad on purpose (Python 3.13 / distutils issues)
    aioredis = None  # type: ignore[assignment]

_redis: Optional["aioredis.Redis"] = None  # type: ignore[name-defined]


async def get_redis() -> Optional["aioredis.Redis"]:  # type: ignore[name-defined]
    """
    Lazily get a Redis client.

    If REDIS_URL is not set or aioredis is unavailable (e.g., Python 3.13
    distutils issue), this returns None so the rest of the app can continue.
    """
    global _redis

    # If Redis is disabled or aioredis couldn't import, just no-op
    if not settings.REDIS_URL or aioredis is None:  # type: ignore[truthy-function]
        return None

    if _redis is None:
        _redis = await aioredis.from_url(  # type: ignore[union-attr]
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
    return _redis


async def add_to_blacklist(jti: str, exp_timestamp: int) -> None:
    """
    Store a token's JTI in Redis until it expires.

    If Redis is unavailable, this becomes a no-op (still safe for this project).
    """
    redis = await get_redis()
    if not redis:
        return

    ttl = max(0, exp_timestamp - int(time.time()))
    await redis.set(jti, "blacklisted", ex=ttl)


async def is_blacklisted(jti: str) -> bool:
    """
    Check if a token JTI is blacklisted.

    If Redis is unavailable, we assume it's not blacklisted.
    """
    redis = await get_redis()
    if not redis:
        return False

    return await redis.exists(jti) == 1
