"""create super admin user

Revision ID: 4fe850a78cba
Revises: 20251230_initial
Create Date: 2026-01-05 10:03:49.168850
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import text
from datetime import datetime

# revision identifiers, used by Alembic.
revision: str = '4fe850a78cba'
down_revision: Union[str, Sequence[str], None] = '20251230_initial'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Cria o usuário SUPER_ADMIN inicial do sistema.
    Essa migration NÃO altera schema, apenas insere dados.
    """

    conn = op.get_bind()

    # Verifica se já existe (idempotência básica)
    result = conn.execute(
        text("SELECT 1 FROM users WHERE email = :email"),
        {"email": "admin@logistiq.com"},
    ).fetchone()

    if not result:
        conn.execute(
            text("""
                INSERT INTO users (
                    name,
                    email,
                    password_hash,
                    role,
                    company_id,
                    is_active,
                    created_at
                )
                VALUES (
                    :name,
                    :email,
                    :password_hash,
                    :role,
                    NULL,
                    true,
                    :created_at
                )
            """),
            {
                "name": "Super Admin",
                "email": "admin@logistiq.com",
                # ⚠️ hash fixo apenas para bootstrap
                # depois você pode trocar via reset de senha
                "password_hash": "$2b$12$9Yt8l7zJxk9cZcO9e7eT2eJ7F0u1p9y1N3dGqv3kXG8bQ1F5FJw8S",
                "role": "SUPER_ADMIN",
                "created_at": datetime.utcnow(),
            },
        )


def downgrade() -> None:
    """
    Remove o usuário SUPER_ADMIN criado por esta migration.
    """

    conn = op.get_bind()
    conn.execute(
        text("DELETE FROM users WHERE email = :email"),
        {"email": "admin@logistiq.com"},
    )
