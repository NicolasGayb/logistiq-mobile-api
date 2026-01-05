from fastapi import APIRouter, Form, Depends, HTTPException
from sqlalchemy.orm import Session
from app.api.schemas import UserCreate, UserMeResponse, UserResponse, UserRole
from app.core.security import get_current_admin_user, get_current_user, hash_password
from app.core.config import SessionLocal
from app.api.models import User
from app.core.database import get_db

router = APIRouter(prefix="/api/users", tags=["Users"])

@router.post(
        "/", 
        response_model=UserResponse, 
        description="Cria um novo usuário (Admin apenas)",
        responses={
            400: {"description": "Email já em uso"}, 
            403: {"description": "Acesso negado"}
            }
        )

def create_user(
    user_create: UserCreate,
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Cria um novo usuário. Apenas administradores podem acessar este endpoint.
    """
    # Não permite criar usuários com papel de ADMIN
    if user_create.role == UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Não é permitido criar usuários com papel de administrador")

    # Verifica se o email já está em uso
    existing_user = db.query(User).filter(User.email == user_create.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="O email informado já está em uso por outro usuário")
    
    # Cria o novo usuário
    user = User(
        name=user_create.name,
        email=user_create.email,
        password_hash=hash_password(user_create.password),
        role=user_create.role,
        company_id=current_admin.company_id # Associa ao mesmo ID da empresa do admin
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@router.get(
        "/me",
        response_model=UserMeResponse,
        description="Retorna os detalhes do usuário autenticado"
)
def get_me(
    current_user: User = Depends(get_current_user)
):
    """
    Retorna os detalhes do usuário autenticado.
    """
    return current_user

@router.get("/all_users", description="Retorna todos os usuários que o usuário pode visualizar", response_model=list[UserResponse])
def get_users_for_current_user(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retorna todos os usuários que o usuário autenticado pode visualizar.
    SUPER_ADMIN vê todos os usuários.
    ADMIN vê usuários da sua empresa.
    MANAGER e USER não têm permissão para ver outros usuários.
    """
    if current_user.role == UserRole.SUPER_ADMIN:
        users = db.query(User).all()
    elif current_user.role == UserRole.ADMIN:
        users = db.query(User).filter(User.company_id == current_user.company_id).all()
    else:
        raise HTTPException(status_code=403, detail="Acesso negado: permissão insuficiente para visualizar outros usuários")
    return users