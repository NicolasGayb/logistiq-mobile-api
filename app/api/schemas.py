import re
from pydantic import BaseModel, EmailStr, validator

class LoginRequest(BaseModel):
    email: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    name: str

    class Config:
        from_attributes = True

class CompanyCreate(BaseModel):
    name: str
    document: str

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