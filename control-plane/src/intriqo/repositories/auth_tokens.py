"""Repository operations for account verification and reset tokens."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.db.models.auth_token import AuthToken, AuthTokenType


class AuthTokenRepository:
    """Persist and atomically consume hashed account tokens."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def create(self, token: AuthToken) -> AuthToken:
        self._db.add(token)
        await self._db.flush()
        return token

    async def get_active(
        self,
        token_hash: str,
        token_type: AuthTokenType,
        now: datetime,
    ) -> AuthToken | None:
        result = await self._db.execute(
            select(AuthToken).where(
                AuthToken.token_hash == token_hash,
                AuthToken.token_type == token_type,
                AuthToken.used_at.is_(None),
                AuthToken.expires_at > now,
            )
        )
        return result.scalar_one_or_none()

    async def invalidate_active(
        self,
        user_id: str,
        token_type: AuthTokenType,
        now: datetime,
    ) -> None:
        await self._db.execute(
            update(AuthToken)
            .where(
                AuthToken.user_id == user_id,
                AuthToken.token_type == token_type,
                AuthToken.used_at.is_(None),
                AuthToken.expires_at > now,
            )
            .values(used_at=now)
        )

    async def consume(self, token_id: str, now: datetime) -> bool:
        """Mark a token used, succeeding only for one concurrent consumer."""
        result = await self._db.execute(
            update(AuthToken)
            .where(
                AuthToken.id == token_id,
                AuthToken.used_at.is_(None),
                AuthToken.expires_at > now,
            )
            .values(used_at=now)
        )
        return result.rowcount == 1
