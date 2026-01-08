from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from urllib.parse import quote_plus
import os

class Settings(BaseSettings):
    app_name: str = "Logistiq Mobile API"
    secret_key: str
    algorithm: str
    access_token_expire_minutes: int
    jwt_secret_key: str

    # Campos de DB opcionais, só usados localmente
    db_user: str | None = None
    db_password: str | None = None
    db_host: str | None = None
    db_port: str | None = None
    db_name: str | None = None

    # Super admin
    super_admin_email: str | None = None
    super_admin_password: str | None = None

    # Config Pydantic V2
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="forbid"
    )

settings = Settings()

# --------------------------
# Configuração do banco
# --------------------------

DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    # Monta a URL a partir dos campos db_ se não estiver no Heroku
    if not all([settings.db_user, settings.db_password, settings.db_host, settings.db_port, settings.db_name]):
        raise Exception("Faltam campos do banco para conexão local ou DATABASE_URL no ambiente.")
    
    db_user = quote_plus(settings.db_user)
    db_password = quote_plus(settings.db_password)
    db_name = quote_plus(settings.db_name)
    db_host = settings.db_host
    db_port = settings.db_port

    DATABASE_URL = f"postgresql+psycopg2://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}?client_encoding=UTF8"

engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

if __name__ == "__main__":
    try:
        with engine.connect() as conn:
            print("Conexão com o banco de dados OK!")
            print("URL:", DATABASE_URL)
    except Exception as e:
        print("Erro ao conectar:", e)
