from fastapi import Depends, HTTPException, status
from app.core.security import get_current_user
from app.api.models import User, UserRole

def require_roles(*allowed_roles: UserRole):
    """Dependency to require specific user roles for access."""
    def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Acesso negado: permissão insuficiente"
            )
        return current_user
    return role_checker