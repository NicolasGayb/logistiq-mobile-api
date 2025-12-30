import logging
from sqlalchemy.exc import IntegrityError
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.api.schemas import LoginRequest, LoginResponse, SignupRequest, UserResponse, UserCreate, LoginResponse
from app.core.security import create_access_token, get_current_user, hash_password, verify_password
from app.core.config import SessionLocal
from app.core.database import get_db
from app.api.models import User, Company

router = APIRouter(prefix="/api", tags=["API"])

# Configura logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

@router.get("/profile", description="Retorna o perfil do usuário autenticado", response_model=UserResponse)
def read_profile(current_user: User = Depends(get_current_user)):
    """
    Retorna o perfil do usuário autenticado.
    """
    return {
        "mensagem": "Você está autenticado",
        "user": {
            "id": current_user.id,
            "email": current_user.email,
            "name": current_user.name
        }
    }

@router.post("/signup", description="Cria uma nova empresa e um usuário administrador associado", response_model=LoginResponse)
def signup(payload: SignupRequest, db: Session = Depends(get_db)):
    """ 
    Cria uma nova empresa e um usuário administrador associado.
    """
    company_data = payload.company
    user_data = payload.user

    # Verifica se os dados da empresa e do usuário foram fornecidos
    if not company_data or not user_data:
        raise HTTPException(status_code=400, detail="Dados de empresa e do usuário são obrigatórios")
    
    # Verifica se o email já está em uso
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="O email informado já está em uso por outro usuário")
    
    # Verifica se a empresa já existe
    existing_company = db.query(Company).filter(Company.document == company_data.document).first()
    if existing_company:
        raise HTTPException(status_code=400, detail="Documento/CNPJ da empresa já está cadastrado")
    
    try:
        new_company = Company(
            name=company_data.name,
            document=company_data.document,
            plan="Basic"  # Plano padrão
        )
        db.add(new_company)
        db.flush() # Para obter o ID da empresa recém-criada

        new_user = User(
            name=user_data.name,
            email=user_data.email,
            password_hash=hash_password(user_data.password),
            role="ADMIN",
            company_id=new_company.id
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        # Gera o token de acesso para o novo usuário
        access_token = create_access_token(
            data={
                "sub": new_user.email,
                "user_id": new_user.id,
                "company_id": new_company.id,
                "role": new_user.role
            }
        )

        logger.info(f"Nova empresa criada: {new_company.name} (ID: {new_company.id})")
        logger.info(f"Novo usuário administrador criado: {new_user.email} (ID: {new_user.id})")

        return {"access_token": access_token, "token_type": "bearer"}
    
    except IntegrityError as e:
        db.rollback()
        logger.error(f"Erro de integridade ao criar empresa ou usuário: {e.orig}")

        # Mensagem detalhada para o cliente
        error_msg = str(e.orig)
        if "users.email" in error_msg:
            raise HTTPException(status_code=400, detail="O email informado já está em uso por outro usuário")
        elif "companies.document" in error_msg:
            raise HTTPException(status_code=400, detail="Documento/CNPJ da empresa já está cadastrado")
        elif "companies.name" in error_msg:
            raise HTTPException(status_code=400, detail="Nome da empresa já está em uso")
        else:
            raise HTTPException(status_code=500, detail="Erro ao criar empresa ou usuário")
        
    except Exception as e:
        db.rollback()
        logger.error(f"Erro ao criar empresa ou usuário: {e}")
        raise HTTPException(status_code=500, detail="Erro ao criar empresa ou usuário")


@router.post("/login", description="Autentica o usuário e retorna um token JWT com informações multi-tenant", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    """
    Login multi-tenant: autentica o usuário e retorna um token JWT com user_id, company_id e role.
    """
    user = db.query(User).filter(User.email == payload.email).first()

    if not user:
        raise HTTPException(status_code=401, detail="Email ou senha inválidos")

    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Email ou senha inválidos")

    # Gera o token de acesso com informações multi-tenant
    access_token = create_access_token(
        data={
            "sub": user.email,
            "user_id": user.id,
            "company_id": user.company_id,
            "role": user.role
        }
    )

    return {"access_token": access_token, "token_type": "bearer"} 

@router.post("/logout", description="Realiza o logout do usuário")
def logout():
    return {"message": "Logout bem-sucedido"}