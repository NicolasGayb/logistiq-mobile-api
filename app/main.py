from fastapi import FastAPI
from app.api.routes import auth, users, companies, products, categories
from app.core.config import engine, Base

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="LogistiQ Mobile API",
    description="API for LogistiQ Mobile Application",
    version="1.0.0"
    )

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(companies.router)
app.include_router(products.router)
app.include_router(categories.router)

@app.get("/api/health", tags=["Health"])
def health_check():
    return {"status": "LogistiQ Mobile API is running"}