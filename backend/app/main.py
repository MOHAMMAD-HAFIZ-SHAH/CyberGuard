from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.config.settings import APP_NAME
from backend.app.api.routes import router

app = FastAPI(
    title=APP_NAME,
    description="Agentic AI for cybersecurity incident investigation",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

app.include_router(router, prefix="/api")


@app.get("/")
def home():
    return {
        "message": "Welcome to CyberGuard",
        "docs": "/docs",
        "health": "/api/health"
    }