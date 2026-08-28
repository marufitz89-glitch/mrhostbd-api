from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api import router as api_router
from domain import router as domain_router


app = FastAPI(
    title="MRHostBD API",
    description="Free Hosting Platform API",
    version="1.0.0"
)


# --------------------------------------------------
# CORS
# --------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------
# Routers
# --------------------------------------------------

app.include_router(
    api_router,
    prefix="/api"
)

app.include_router(
    domain_router,
    prefix="/domain"
)


# --------------------------------------------------
# Root
# --------------------------------------------------

@app.get("/")
async def root():
    return {
        "success": True,
        "name": "MRHostBD",
        "message": "MRHostBD API is running",
        "version": "1.0.0"
    }


# --------------------------------------------------
# Health Check
# --------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "online"
    }