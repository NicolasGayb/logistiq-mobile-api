"""Initial migration: create users and companies tables

Revision ID: 20251230_initial
Revises: 
Create Date: 2025-12-30 16:30:00.000000

"""
from alembic import op
import sqlalchemy as sa
from datetime import datetime

# revision identifiers, used by Alembic.
revision = '20251230_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Criação da tabela companies
    op.create_table(
        'companies',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('name', sa.String, nullable=False),
        sa.Column('document', sa.String, nullable=False, unique=True),
        sa.Column('plan', sa.String, nullable=True),
        sa.Column('is_active', sa.Boolean, default=True),
        sa.Column('created_at', sa.DateTime, default=datetime.utcnow),
    )

    # Criação da tabela users
    op.create_table(
        'users',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('name', sa.String, nullable=True),
        sa.Column('email', sa.String, nullable=False, unique=True),
        sa.Column('password_hash', sa.String, nullable=False),
        sa.Column('role', sa.String, nullable=True),
        sa.Column('company_id', sa.Integer, sa.ForeignKey('companies.id'), nullable=True),
        sa.Column('is_active', sa.Boolean, default=True),
        sa.Column('created_at', sa.DateTime, default=datetime.utcnow),
    )


def downgrade():
    op.drop_table('users')
    op.drop_table('companies')
