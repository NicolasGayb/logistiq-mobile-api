from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query
from app.api.schemas import ProductResponse, UserRole, ProductCreate
from app.api.models import Product, User
from app.core.security import get_current_user
from app.core.database import get_db
from sqlalchemy.orm import Session


router = APIRouter(prefix="/api/products", tags=["Products"])

@router.get("/", response_model=List[ProductResponse], description="Lista produtos com filtros opcionais de categoria e empresa")
def get_products(
    category_id: Optional[int] = Query(None, description="Filtra por categoria"),
    company_id: Optional[int] = Query(None, description="Filtra por empresa (somente SUPER_ADMIN pode filtrar por qualquer empresa)"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retorna produtos filtrados por categoria e/ou empresa.
    
    Regras de acesso:
    - SUPER_ADMIN: pode ver todos os produtos e filtrar por qualquer empresa.
    - ADMIN: só vê produtos da própria empresa, filtro company_id é ignorado.
    - MANAGER: só vê produtos ativos da própria empresa.
    - OUTROS: não têm acesso.
    """
    query = db.query(Product)

    # Controle de acesso por role
    if current_user.role == UserRole.SUPER_ADMIN:
        if company_id:
            query = query.filter(Product.company_id == company_id)
    elif current_user.role == UserRole.ADMIN:
        query = query.filter(Product.company_id == current_user.company_id)
    elif current_user.role == UserRole.MANAGER:
        query = query.filter(
            Product.company_id == current_user.company_id,
            Product.is_active == True
        )
    else:
        raise HTTPException(status_code=403, detail="Acesso negado: permissão insuficiente")

    # Filtro opcional por categoria
    if category_id:
        query = query.filter(Product.category_id == category_id)

    return query.all()

@router.get("/get/{product_id}", response_model=ProductResponse, description="Retorna os detalhes de um produto específico")
def get_product(
    product_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retorna os detalhes de um produto específico."""
    product = db.query(Product).filter(Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Produto não encontrado")

    if current_user.role == UserRole.SUPER_ADMIN:
        return product
    elif current_user.role == UserRole.ADMIN:
        if product.company_id != current_user.company_id:
            raise HTTPException(status_code=403, detail="Acesso negado: permissão insuficiente")
        return product
    elif current_user.role == UserRole.MANAGER:
        if product.company_id != current_user.company_id or not product.is_active:
            raise HTTPException(status_code=403, detail="Acesso negado: permissão insuficiente")
        return product
    else:
        raise HTTPException(status_code=403, detail="Acesso negado: permissão insuficiente")

@router.post("/create", response_model=ProductResponse, description="Cria um novo produto (Admin apenas)")
def create_product(
    product: ProductCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Cria um novo produto. Apenas administradores podem acessar este endpoint."""
    if current_user.role not in [UserRole.ADMIN, UserRole.SUPER_ADMIN]:
        raise HTTPException(status_code=403, detail="Acesso negado: apenas administradores podem criar produtos")

    new_product = Product(
        name=product.name,
        sku=product.sku,
        description=product.description,
        price=product.price,
        is_active=product.is_active,
        company_id=current_user.company_id
    )
    db.add(new_product)
    db.commit()
    db.refresh(new_product)
    return new_product

@router.delete("/delete/{product_id}", description="Deleta um produto (Admin apenas)")
def delete_product(
    product_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Deleta um produto. Apenas administradores podem acessar este endpoint."""
    if current_user.role not in [UserRole.ADMIN, UserRole.SUPER_ADMIN]:
        raise HTTPException(status_code=403, detail="Acesso negado: apenas administradores podem deletar produtos")

    product = db.query(Product).filter(Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Produto não encontrado")

    if current_user.role == UserRole.ADMIN and product.company_id != current_user.company_id:
        raise HTTPException(status_code=403, detail="Acesso negado: permissão insuficiente")

    db.delete(product)
    db.commit()
    return {f"Produto {product_id} deletado com sucesso."}

@router.put("/update/{product_id}", response_model=ProductResponse, description="Atualiza um produto (Admin apenas)")
def update_product(
    product_id: int,
    product_update: ProductCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Atualiza um produto. Apenas administradores podem acessar este endpoint."""
    if current_user.role not in [UserRole.ADMIN, UserRole.SUPER_ADMIN]:
        raise HTTPException(status_code=403, detail="Acesso negado: apenas administradores podem atualizar produtos")

    product = db.query(Product).filter(Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Produto não encontrado")

    if current_user.role == UserRole.ADMIN and product.company_id != current_user.company_id:
        raise HTTPException(status_code=403, detail="Acesso negado: permissão insuficiente")

    product.name = product_update.name
    product.sku = product_update.sku
    product.description = product_update.description
    product.price = product_update.price
    product.is_active = product_update.is_active

    db.commit()
    db.refresh(product)
    return product

