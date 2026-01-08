from datetime import timedelta
import logging
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError
import jwt
from sqlalchemy.exc import IntegrityError
from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
from app.api.schemas import ForgotPasswordRequest, LoginResponse, SignupRequest, LoginResponse, PasswordChangeRequest, ResetPasswordRequest, SignupResponse
from app.core.dependencies import authenticate_user
from app.core.security import create_access_token, get_current_user, hash_password, verify_password
from app.core.database import get_db
from app.api.models import User, Company

router = APIRouter(prefix="/api", tags=["Auth"])

# Configura logger
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

@router.post("/signup", description="Cria uma nova empresa e um usuário administrador associado", response_model=LoginResponse)
def signup(payload: SignupRequest, db: Session = Depends(get_db)):
    """ 
    Cria uma nova empresa e um usuário administrador associado.
    """
    logger.info("📩 [SIGNUP] Requisição recebida")

    logger.info(
        f"📦 [SIGNUP] Payload recebido | "
        f"company={{name={payload.company.name}, document={payload.company.document}}} | "
        f"user={{name={payload.user.name}, email={payload.user.email}}}"
    )

    company_data = payload.company
    user_data = payload.user

    # Verifica se os dados da empresa e do usuário foram fornecidos
    if not company_data or not user_data:
        logger.warning("⚠️ [SIGNUP] Dados de empresa ou usuário não fornecidos")
        raise HTTPException(status_code=400, detail="Dados de empresa e do usuário são obrigatórios")
    
    # Verifica se o email já está em uso
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    logger.warning(f"⚠️ [SIGNUP] Email já em uso: {user_data.email}")
    if existing_user:
        raise HTTPException(status_code=400, detail="O email informado já está em uso por outro usuário")
    
    # Verifica se a empresa já existe
    existing_company = db.query(Company).filter(Company.document == company_data.document).first()
    if existing_company:
        logger.warning(f"⚠️ [SIGNUP] Documento/CNPJ da empresa já cadastrado: {company_data.document}")
        raise HTTPException(status_code=400, detail="Documento/CNPJ da empresa já está cadastrado")
    
    try:
        new_company = Company(
            name=company_data.name,
            document=company_data.document,
            plan="Basic"  # Plano padrão
        )
        logger.info("🏗️ [SIGNUP] Criando empresa")
        db.add(new_company)
        db.flush() # Para obter o ID da empresa recém-criada

        logger.info(f"🏢 [SIGNUP] Empresa criada | id={new_company.id}")

        new_user = User(
            name=user_data.name,
            email=user_data.email,
            password_hash=hash_password(user_data.password),
            role="ADMIN",
            company_id=new_company.id
        )

        logger.info("👤 [SIGNUP] Criando usuário ADMIN")
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        logger.info(f"✅ [SIGNUP] Usuário criado | id={new_user.id}")

        logger.info(
        f"🔐 [SIGNUP] Gerando token | "
        f"user_id={new_user.id} | company_id={new_company.id} | role={new_user.role}"
        )

        # Gera o token de acesso para o novo usuário
        access_token = create_access_token(
            data={
                "sub": new_user.email,
                "user_id": new_user.id,
                "company_id": new_company.id,
                "role": new_user.role
            }
        )
        logger.info(
       f"📤 [SIGNUP] Resposta enviada com sucesso | user_id={new_user.id}"
        )

        logger.info(f"Nova empresa criada: {new_company.name} (ID: {new_company.id})")
        logger.info(f"Novo usuário administrador criado: {new_user.email} (ID: {new_user.id})")

        return {
            "access_token": access_token, 
            "token_type": "bearer",
            "user": {
                "id": new_user.id,
                "name": new_user.name,
                "email": new_user.email,
                "role": new_user.role,
                "company_id": new_user.company_id
            }
        }
    
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

@router.post(
        "/login", 
        description="Autentica o usuário e retorna um token JWT com informações multi-tenant", 
        response_model=LoginResponse
    )
def login(
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: Session = Depends(get_db)):
    """
    Login multi-tenant: autentica o usuário e retorna um token JWT com user_id, company_id e role.
    """
    user = authenticate_user(db, form_data.username, form_data.password)

    if not user or not user.is_active:
        logger.warning(f"⚠️ [LOGIN] Falha na autenticação para o email: {form_data.username}")
        raise HTTPException(status_code=401, detail="Email ou senha inválidos")

    if not verify_password(form_data.password, user.password_hash):
        logger.warning(f"⚠️ [LOGIN] Senha inválida para o email: {form_data.username}")
        raise HTTPException(status_code=401, detail="Email ou senha inválidos")

    # Gera o token de acesso com informações multi-tenant
    logger.warning(f"🔐 [LOGIN] Gerando token para o usuário: {user.email}")
    access_token = create_access_token(
        data={"sub": str(user.id), "role": user.role.name, "company_id": user.company_id}
    )

    logger.info(f"📤 [LOGIN] Login bem-sucedido para o usuário: {user.email}")
    return {
        "access_token": access_token, 
        "token_type": "bearer", 
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role,
            "company_id": user.company_id,
            "is_active": user.is_active
        }
    }

@router.post("/logout", description="Realiza o logout do usuário")
def logout():
    return {"message": "Logout bem-sucedido"}

@router.put("/users/change-password", description="Permite que o usuário autenticado altere sua senha")
def change_password(
    request: PasswordChangeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Permite que o usuário autenticado altere sua senha.
    """
    # Verifica se a senha atual está correta
    if not verify_password(request.current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Senha atual incorreta"
        )
    
    # Atualiza a senha do usuário
    current_user.password_hash = hash_password(request.new_password)
    db.add(current_user)
    db.commit()
    db.refresh(current_user)

    return {f"Senha alterada com sucesso para o usuário {current_user.email}."}

@router.post("/users/forgot-password", description="Inicia o processo de recuperação de senha para o usuário")
def forgot_password(
    request: ForgotPasswordRequest, 
    db: Session = Depends(get_db)
):
    """
    Inicia o processo de recuperação de senha para o usuário.
    """
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        return {"message": "Se o email estiver cadastrado, você receberá instruções para recuperação de senha."}
    
    # Gera um token temporário (expira em 15 minutos)
    reset_token = create_access_token(
        data={"sub": str(user.id)}, 
        expires_delta=timedelta(minutes=15)
    )

    # Cria o link de redefinição de senha
    reset_link = f"http://localhost:3000/reset-password?token={reset_token}"

    # Envia email com instruções de recuperação
    send_email(
        to=user.email,
        subject="Recuperação de Senha",
        body=f"Use o seguinte token para redefinir sua senha: {reset_token}. Este token expira em 15 minutos."
    )

    return {"message": "Se o email estiver cadastrado, você receberá instruções para recuperação de senha."}

@router.post("/users/reset-password", description="Redefine a senha usando token")
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    """
    Redefine a senha do usuário usando o token enviado por email.
    """
    # Valida o token e obtém o user_id
    try:
        payload = jwt.decode(
            request.token,
            settings.jwt_secret_key,
            algorithms=[settings.algorithm]
        )
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Token inválido ou expirado")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")
    
    # Busca o usuário no banco de dados
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    
    # Atualiza a senha
    user.password_hash = hash_password(request.new_password)
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return {"message": "Senha redefinida com sucesso"}