from fastapi import APIRouter, Depends, HTTPException
from app.api.models import Company, User
from app.core.dependencies import require_super_admin
from app.core.database import get_db
from app.core.security import get_current_user
from sqlalchemy.orm import Session

router = APIRouter(prefix="/api/companies", tags=["Companies"])

@router.get("/all-companies")
def get_all_companies(
    current_user: User = Depends(require_super_admin)
):
    """Retorna todas as empresas cadastradas no sistema. Acesso restrito a Super Admins."""
    companies = get_db.query(Company).all()
    return companies

@router.get("/company-info")
def get_company_for_current_user(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retorna informações da empresa do usuário autenticado."""
    company = db.query(Company).filter(Company.id == current_user.company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Empresa não encontrada")
    return company