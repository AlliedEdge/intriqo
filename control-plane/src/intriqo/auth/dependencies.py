"""FastAPI authentication dependencies.

Usage:

    @router.get("/protected")
    async def protected(user: CurrentUser = Depends(require_analyst)):
        ...
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError

from intriqo.auth.tokens import decode_access_token

_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class CurrentUser:
    """Authenticated user identity extracted from the JWT."""
    user_id: str
    username: str
    role: str


def _extract_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> CurrentUser:
    """Validate the Bearer token and return the authenticated user."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "MISSING_TOKEN", "message": "Authentication required"}},
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_access_token(credentials.credentials)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "INVALID_TOKEN", "message": "Token is invalid or expired"}},
            headers={"WWW-Authenticate": "Bearer"},
        )
    return CurrentUser(
        user_id=payload.get("user_id", ""),
        username=payload["sub"],
        role=payload.get("role", "ANALYST"),
    )


# ── Role-based dependency factories ──────────────────────────────────────────

def _require_role(*allowed_roles: str):
    def dep(user: CurrentUser = Depends(_extract_user)) -> CurrentUser:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": {
                        "code": "FORBIDDEN",
                        "message": f"Role '{user.role}' is not permitted for this action",
                    }
                },
            )
        return user
    return dep


# Convenience dependencies — import these in routers
require_any    = _extract_user                                        # any authenticated user
require_analyst = _require_role("ADMIN", "ANALYST")                  # analysts + admins
require_agent   = _require_role("ADMIN", "ANALYST", "AGENT")         # + agent service accounts
require_admin   = _require_role("ADMIN")                             # admin only

# Type alias for cleaner function signatures
AuthUser = Annotated[CurrentUser, Depends(require_any)]
AnalystUser = Annotated[CurrentUser, Depends(require_analyst)]
AgentUser = Annotated[CurrentUser, Depends(require_agent)]
AdminUser = Annotated[CurrentUser, Depends(require_admin)]
