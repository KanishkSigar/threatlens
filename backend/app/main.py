"""
ThreatLens — AI-Powered Phishing Detection Platform
Main FastAPI application entry point.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.database import init_db
from app.routers import health, auth, scan
from app.services.ml_predictor import load_model

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    # ─── Startup ────────────────────────────────────────────
    logger.info("🔍 Starting %s v%s", settings.APP_NAME, settings.APP_VERSION)

    # Initialize database tables
    await init_db()
    logger.info("✅ Database initialized")

    # Load ML model
    load_model()
    logger.info("✅ ML predictor ready")

    logger.info("🚀 %s is ready!", settings.APP_NAME)

    yield

    # ─── Shutdown ───────────────────────────────────────────
    logger.info("👋 Shutting down %s", settings.APP_NAME)


# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "AI-Powered Phishing Detection API. "
        "Scan URLs and emails to detect phishing threats "
        "with machine learning and real-time analysis."
    ),
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware — allow iOS app to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to your app's domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(health.router)
app.include_router(auth.router)
app.include_router(scan.router)


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint — API welcome message."""
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "health": "/health",
        "description": "AI-Powered Phishing Detection Platform",
    }
