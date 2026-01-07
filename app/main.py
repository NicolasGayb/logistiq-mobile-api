import os
from fastapi import FastAPI
from app.api.routes import auth, users, companies, products, categories
from app.core.config import engine, Base
from fastapi.middleware.cors import CORSMiddleware

# Cria tabelas
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="LogistiQ Mobile API",
    description="API for LogistiQ Mobile Application",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Rotas
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(companies.router)
app.include_router(products.router)
app.include_router(categories.router)

# Health check
@app.get("/api/health", tags=["Health"])
def health_check():
    return {"status": "LogistiQ Mobile API is running"}

# Rodar com uvicorn localmente
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("run:app", host="0.0.0.0", port=port, reload=True)