from fastapi import APIRouter, Form, Depends, HTTPException
from sqlalchemy.orm import Session
from app.api.schemas import UserCreate, UserResponse, UserRole
from app.core.security import get_current_admin_user, hash_password
from app.core.config import SessionLocal
from app.api.models import User

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
    name: str = Form(..., description="Nome do usuário", example="João Silva"),
    email: str = Form(..., description="Email do usuário", example="joao.silva@example.com"),
    password: str = Form(..., description="Senha do usuário", example="senha123"),
    role: UserRole = Form(UserRole.USER, description="Papel do usuário (USER ou MANAGER)"),
    current_admin = Depends(get_current_admin_user),
    db: Session = Depends(SessionLocal)
):
    """
    Cria um novo usuário. Apenas administradores podem acessar este endpoint.
    """
    # Verifica se o papel do usuário é válido
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
        hashed_password=hash_password(user_create.password),
        role=user_create.role,
        company_id=current_admin.company_id # Associa ao mesmo ID da empresa do admin
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user