from sqlalchemy import Column, Enum, Float, Integer, String, ForeignKey, Boolean, DateTime, func
from sqlalchemy.orm import relationship
from datetime import datetime
from app.api.schemas import UserRole
from app.core.config import Base

class Company(Base):
    __tablename__ = "companies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    document = Column(String, unique=True, nullable=False)
    plan = Column(String, nullable=False, default="Basic") # Planos: Basic, Pro, Enterprise
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    users = relationship("User", back_populates="company") # Uma empresa pode ter muitos usuários
    products = relationship("Product", back_populates="company") # Uma empresa pode ter muitos produtos
    categories = relationship("Categories", back_populates="company") # Uma empresa pode ter muitas categorias

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.USER) # Roles: SUPER_ADMIN | ADMIN | MANAGER | USER
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    company = relationship("Company", back_populates="users") # Muitos usuários pertencem a uma empresa

class Categories(Base):
    __tablename__ = "categories"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(String, nullable=True)

    # Multi-tenant: vínculo com empresa
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False)
    company = relationship("Company", back_populates="categories")

    # Produtos relacionados
    products = relationship("Product", back_populates="category")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class Product(Base):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(String, nullable=True)
    sku = Column(String(50), unique=True, nullable=True, index=True)  # código de referência
    price = Column(Float, nullable=False)
    quantity_in_stock = Column(Integer, nullable=False, default=0)
    is_active = Column(Boolean, default=True)
    
    # Multi-tenant: vínculo com empresa
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False)
    company = relationship("Company", back_populates="products")

    # Categorias simples
    category_id = Column(Integer, ForeignKey("categories.id"), nullable=True)
    category = relationship("Categories", back_populates="products")
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())