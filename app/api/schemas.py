from datetime import datetime
import re
from pydantic import BaseModel, EmailStr, validator, Field
from typing import Annotated
from enum import Enum

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="admin@empresa.com")
    password: str = Field(..., example="senha123")

class UserRole(str, Enum):
    SUPER_ADMIN = "SUPER_ADMIN"
    ADMIN = "ADMIN"
    MANAGER = "MANAGER"
    USER = "USER"

class UserResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    role: UserRole
    company_id: Annotated[int | None, Field(example=1)]

    model_config = {"from_attributes": True}

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class UserCreate(BaseModel):
    name: str = Field(..., example="João Silva")
    email: EmailStr = Field(..., example="joao@empresa.com")
    password: str = Field(..., example="senha123")
    role: UserRole = Field(default=UserRole.USER, description="Role do usuário")

class CompanyCreate(BaseModel):
    name: str = Field(..., example="Empresa X")
    document: str = Field(..., example="12.345.678/0001-90")

    @validator("document")
    def validate_document(cls, v):
        # Remove tudo que não for número
        cnpj_numbers = re.sub(r'\D', '', v)
        if len(cnpj_numbers) != 14:
            raise ValueError("Documento/CNPJ inválido. Deve conter 14 dígitos numéricos.")
        return v

class SignupRequest(BaseModel):
    company: CompanyCreate
    user: UserCreate

    model_config = {"from_attributes": True}

class SignupResponse(BaseModel):
    id: str
    name: str
    email: EmailStr
    access_token: str
    token_type: str = "bearer"

class UserMeResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    role: UserRole
    company_id: int
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}

class CompanyResponse(BaseModel):
    id: int
    name: str
    document: str
    plan: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}

class ProductCreate(BaseModel):
    name: str
    description: str | None
    sku: str
    price: float
    is_active: bool = True
    category_id: int

class ProductResponse(BaseModel):
    id: int
    name: str
    description: str | None
    price: float
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}

class CategoryCreate(BaseModel):
    name: str
    description: str | None

class CategoryResponse(BaseModel):
    id: int
    name: str
    description: str | None
    created_at: datetime

    model_config = {"from_attributes": True}

class PasswordChangeRequest(BaseModel):
    current_password: str = Field(..., min_length=6, example="senhaAtual123")
    new_password: str = Field(..., min_length=6, example="senhaNova456")

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=6, example="senhaNova456")