"""
ShieldSphere FastAPI Application Entry Point
"""
import asyncio
import os
import sys
import truststore

# Fix for Windows: psycopg3 async requires SelectorEventLoop
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# Use the operating system's managed certificate store for outbound HTTPS.
# This keeps verification enabled while supporting locally trusted corporate
# and development certificate authorities on Windows.
truststore.inject_into_ssl()

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
import structlog

from app.core.config import settings
from app.core.rate_limit import limiter
from app.api.v1.router import api_router
from app.workers.auto_block import init_scheduler, shutdown_scheduler

# Configure structured logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_log_level,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.BoundLogger,
    logger_factory=structlog.PrintLoggerFactory(),
)
logging.basicConfig(level=logging.INFO if settings.APP_ENV != "development" else logging.DEBUG)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    logger.info("Starting ShieldSphere backend...")

    # Test database connection
    from app.db.session import engine
    try:
        async with engine.connect() as conn:
            from sqlalchemy import text
            await conn.execute(text("SELECT 1"))
        logger.info("✅ Database connection OK")
    except Exception as e:
        logger.error(f"❌ Database connection failed: {e}")
        raise

    # Start background scheduler
    try:
        init_scheduler()
        logger.info("✅ Background scheduler started")
    except Exception as e:
        logger.warning(f"Scheduler start warning: {e}")

    yield

    # Shutdown
    logger.info("Shutting down ShieldSphere backend...")
    try:
        shutdown_scheduler()
    except Exception:
        pass
    await engine.dispose()


app = FastAPI(
    title="ShieldSphere API",
    description="Enterprise Account Security Platform — AI-powered threat detection, behavioral analytics, and attack simulation",
    version="1.0.0",
    docs_url="/docs" if settings.API_DOCS_ENABLED else None,
    redoc_url="/redoc" if settings.API_DOCS_ENABLED else None,
    lifespan=lifespan,
)

# Reject spoofed Host headers before requests reach application routes.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts_list)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
app.add_middleware(
    CORSMiddleware,
    # Reflect any Origin for CORS_ORIGINS="*" so credentialed authentication
    # requests remain valid.  A literal wildcard is rejected by browsers when
    # Access-Control-Allow-Credentials is enabled.
    allow_origins=[] if settings.cors_allow_all_origins else settings.cors_origins_list,
    allow_origin_regex=".*" if settings.cors_allow_all_origins else None,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API router
app.include_router(api_router)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    from app.db.session import engine
    from sqlalchemy import text
    import redis.asyncio as aioredis

    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception:
        logger.exception("Database health check failed")
        db_status = "error"

    redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        await redis_client.ping()
        redis_status = "ok"
    except Exception:
        logger.exception("Redis health check failed")
        redis_status = "error"
    finally:
        await redis_client.aclose()

    payload = {
        "status": "ok" if db_status == "ok" and redis_status == "ok" else "degraded",
        "service": "ShieldSphere API",
        "version": "1.0.0",
        "database": db_status,
        "redis": redis_status,
    }
    if db_status != "ok" or redis_status != "ok":
        return JSONResponse(status_code=503, content=payload)
    return payload


@app.get("/")
async def root():
    return {
        "service": "ShieldSphere Enterprise Security Platform",
        "docs": "/docs",
        "health": "/health",
        "version": "1.0.0",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=os.environ.get("SHIELDSPHERE_HOST_ADDRESS", "127.0.0.1"),
        port=int(os.environ.get("SHIELDSPHERE_PORT", "8000")),
    )
