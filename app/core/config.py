# app/core/config.py
import os
from urllib.parse import quote_plus
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "LogistiQ Mobile API"
    secret_key: str
    algorithm: str
    access_token_expire_minutes: int
    jwt_secret_key: str

    # Super admin
    super_admin_email: str | None = None
    super_admin_password: str | None = None

    # Configuração Pydantic V2
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="forbid"  # extra fields proibidos
    )

settings = Settings()

# --------------------------
# Configuração do banco
# --------------------------

# Se existir DATABASE_URL no ambiente (Heroku), usa ela
DATABASE_URL = os.environ.get("DATABASE_URL")

# Se não existir (local), monta a URL a partir do .env
if not DATABASE_URL:
    db_user = quote_plus(os.environ.get("DB_USER", "postgres"))
    db_password = quote_plus(os.environ.get("DB_PASSWORD", "senha"))
    db_host = os.environ.get("DB_HOST", "localhost")
    db_port = os.environ.get("DB_PORT", "5432")
    db_name = os.environ.get("DB_NAME", "logistiqmobile")

    DATABASE_URL = f"postgresql+psycopg2://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}?client_encoding=UTF8"

# Cria engine e sessão
engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Teste de conexão
if __name__ == "__main__":
    try:
        with engine.connect() as conn:
            print("Conexão com o banco de dados OK!")
            print("URL:", DATABASE_URL)
    except Exception as e:
        print("Erro ao conectar:", e)