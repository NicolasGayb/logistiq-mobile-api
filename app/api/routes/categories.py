from fastapi import HTTPException, APIRouter, Depends, Query
from typing import List, Optional
from app.api.schemas import CategoryResponse, UserRole
from app.api.models import Categories, User
from app.core.security import get_current_user
from app.core.database import get_db
from sqlalchemy.orm import Session

router = APIRouter(prefix="/api/categories", tags=["Categories"])

@router.get("/", response_model=List[CategoryResponse], description="Lista categorias com filtros opcionais de empresa")
def get_categories(
    company_id: Optional[int] = Query(None, description="Filtra por empresa (somente SUPER_ADMIN pode filtrar por qualquer empresa)"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retorna categorias filtradas por empresa.
    
    Regras de acesso:
    - SUPER_ADMIN: pode ver todas as categorias e filtrar por qualquer empresa.
    - ADMIN e MANAGER: só vê categorias da própria empresa.
    - OUTROS: não têm acesso.
    """
    query = db.query(Categories)

    # Controle de acesso por role
    if current_user.role == UserRole.SUPER_ADMIN:
        if company_id:
            query = query.filter(Categories.company_id == company_id)
    elif current_user.role in [UserRole.ADMIN, UserRole.MANAGER]:
        query = query.filter(Categories.company_id == current_user.company_id)
    else:
        raise HTTPException(status_code=403, detail="Acesso negado: permissão insuficiente")
    return query.all()

@router.get("/get/{category_id}", response_model=CategoryResponse, description="Retorna os detalhes de uma categoria específica")
def get_category(
    category_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retorna os detalhes de uma categoria específica."""
    category = db.query(Categories).filter(Categories.id == category_id).first()
    if not category:
        raise HTTPException(status_code=404, detail="Categoria não encontrada")

    # Verifica permissão de acesso
    if current_user.role == UserRole.SUPER_ADMIN:
        pass  # Acesso total
    elif current_user.role in [UserRole.ADMIN, UserRole.MANAGER]:
        if category.company_id != current_user.company_id:
            raise HTTPException(status_code=403, detail="Acesso negado: permissão insuficiente")
    else:
        raise HTTPException(status_code=403, detail="Acesso negado: permissão insuficiente")

    return category

@router.post("/", response_model=CategoryResponse, description="Cria uma nova categoria (Admins apenas)")
def create_category(
    name: str,
    description: Optional[str] = None,
    current_admin: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Cria uma nova categoria. Apenas administradores podem acessar este endpoint.
    """
    if current_admin.role not in [UserRole.ADMIN, UserRole.SUPER_ADMIN]:
        raise HTTPException(status_code=403, detail="Acesso negado: apenas Admins podem criar categorias")

    new_category = Categories(
        name=name,
        description=description,
        company_id=current_admin.company_id
    )
    db.add(new_category)
    db.commit()
    db.refresh(new_category)
    return new_category