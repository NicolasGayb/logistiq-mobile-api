from datetime import datetime
import re
from pydantic import BaseModel, EmailStr, validator, Field
from typing import Annotated
from enum import Enum

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., example="admin@empresa.com")
    password: str = Field(..., example="senha123")

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserRole(str, Enum):
    ADMIN = "ADMIN"
    MANAGER = "MANAGER"
    USER = "USER"

class UserCreate(BaseModel):
    name: str = Field(..., example="João Silva")
    email: EmailStr = Field(..., example="joao@empresa.com")
    password: str = Field(..., example="senha123")
    role: UserRole = Field(default=UserRole.USER, description="Role do usuário")

class UserResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    role: UserRole

    model_config = {"from_attributes": True}

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

class UserMeResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    role: UserRole
    company_id: int
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}