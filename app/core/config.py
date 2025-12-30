from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from urllib.parse import quote_plus

class Settings(BaseSettings):
    app_name: str = "Logistiq Mobile API"
    secret_key: str
    algorithm: str
    access_token_expire_minutes: int
    db_user: str
    db_password: str
    db_host: str
    db_port: str
    db_name: str
    jwt_secret_key: str

    # Configuração Pydantic V2
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="forbid"
    )

settings = Settings()

# Escapar credenciais e nome do banco para evitar erros de encoding
db_user = quote_plus(settings.db_user)
password = quote_plus(settings.db_password)
db_name = quote_plus(settings.db_name)

DATABASE_URL = f"postgresql+psycopg://{db_user}:{password}@{settings.db_host}:{settings.db_port}/{db_name}?client_encoding=UTF8"

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