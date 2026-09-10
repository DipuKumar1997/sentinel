"""Role-based access control dependencies for FastAPI routes."""
from collections.abc import Callable

from fastapi import Depends, HTTPException, status

from app.models.rbac import RoleName
from app.models.user import User
from app.security.deps import get_current_user

# Coarse role hierarchy used for "at least this level" checks.
_ROLE_RANK = {
    RoleName.EMPLOYEE: 0,
    RoleName.SECURITY_ANALYST: 1,
    RoleName.INVESTIGATOR: 2,
    RoleName.SOC_ADMIN: 3,
    RoleName.ORG_ADMIN: 4,
    RoleName.PLATFORM_ADMIN: 5,
}


def require_roles(*allowed: RoleName) -> Callable:
    """Dependency factory restricting a route to an explicit set of roles."""

    async def _checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action.",
            )
        return current_user

    return _checker


def require_min_role(minimum: RoleName) -> Callable:
    """Dependency factory allowing the given role or any role ranked above it."""

    async def _checker(current_user: User = Depends(get_current_user)) -> User:
        if _ROLE_RANK.get(current_user.role, -1) < _ROLE_RANK.get(minimum, 99):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have sufficient privileges for this action.",
            )
        return current_user

    return _checker
