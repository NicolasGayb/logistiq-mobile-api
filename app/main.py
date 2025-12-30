from fastapi import FastAPI
from app.api.routes.auth import router as auth_router
from app.core.config import engine, Base

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="LogistiQ Mobile API",
    description="API for LogistiQ Mobile Application",
    version="1.0.0"
    )

app.include_router(auth_router)

@app.get("/api/health", tags=["Health"])
def health_check():
    return {"status": "LogistiQ Mobile API is running"}