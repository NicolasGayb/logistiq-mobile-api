from fastapi import Depends, HTTPException, status
from app.core.security import get_current_user, verify_password
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

def require_super_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.SUPER_ADMIN:
        raise HTTPException(status_code=403, detail="Acesso negado: apenas Super Admin")
    return current_user

def require_admin_or_super(current_user: User = Depends(get_current_user)):
    if current_user.role not in [UserRole.ADMIN, UserRole.SUPER_ADMIN]:
        raise HTTPException(status_code=403, detail="Acesso negado: apenas Admin ou Super Admin")
    return current_user

def require_manager_or_higher(current_user: User = Depends(get_current_user)):
    if current_user.role not in [UserRole.MANAGER, UserRole.ADMIN, UserRole.SUPER_ADMIN]:
        raise HTTPException(status_code=403, detail="Acesso negado: apenas Manager ou superior")
    return current_user

def authenticate_user(db, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if user and verify_password(password, user.password_hash):
        return user
    return None