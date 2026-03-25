"""FastAPI application entry point."""

import logging
import sys
from pathlib import Path

from contextlib import asynccontextmanager

# Ensure scheduler and app logs are visible in Docker/uvicorn
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    stream=sys.stdout,
    force=True,
)

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.config import settings
from app.routers import (
    accounts,
    compliance,
    drift,
    executive,
    iam_graph,
    inventory,
    jira,
    policies,
    risk,
    scans,
    security_graph,
    violations,
    websocket,
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle — runs scheduled scans."""
    import threading
    from uuid import uuid4

    from app.dependencies import (
        get_boto3_session,
        get_evaluator,
        get_settings as _get_settings,
        get_state_manager,
    )
    from app.routers.scans import _run_scan

    if not settings.aws_account_id:
        logger.warning(
            "AWS_ACCOUNT_ID is not set. "
            "Set it in .env for production use."
        )
    interval = settings.scan_interval_minutes * 60  # seconds
    stop_event = threading.Event()

    def _scheduler_loop():
        """Run in a daemon thread — fires _run_scan every interval."""
        logger.info(
            "Scheduled scanner started — interval: %d min",
            settings.scan_interval_minutes,
        )
        while not stop_event.wait(timeout=0):
            scan_id = str(uuid4())
            logger.info("Auto-scan starting [%s]", scan_id)
            try:
                _run_scan(
                    scan_id=scan_id,
                    session=get_boto3_session(),
                    settings=_get_settings(),
                    evaluator=get_evaluator(),
                    state_manager=get_state_manager(),
                )
                logger.info(
                    "Auto-scan complete [%s]", scan_id
                )
            except Exception as exc:
                logger.error(
                    "Auto-scan [%s] crashed: %s",
                    scan_id, exc, exc_info=True,
                )
            # Wait for the next interval (or until stop_event is set)
            stop_event.wait(timeout=interval)

    scheduler = threading.Thread(
        target=_scheduler_loop,
        name="cloudline-scheduler",
        daemon=True,
    )
    scheduler.start()

    yield  # application is running

    logger.info("Stopping scheduled scanner…")
    stop_event.set()
    scheduler.join(timeout=10)


app = FastAPI(
    title="CloudLine",
    description=(
        "OPA-based AWS misconfiguration "
        "detection platform"
    ),
    version=settings.app_version,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# --- CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        o.strip()
        for o in settings.cors_origins.split(",")
        if o.strip()
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


# --- Security Headers ---
@app.middleware("http")
async def security_headers(
    request: Request, call_next
):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = (
        "nosniff"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers[
        "Content-Security-Policy"
    ] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    response.headers[
        "Strict-Transport-Security"
    ] = "max-age=31536000; includeSubDomains"
    path = request.url.path
    if not path.startswith(
        "/api/docs"
    ) and not path.startswith("/api/openapi"):
        response.headers[
            "Cache-Control"
        ] = "no-store, no-cache, must-revalidate"
    response.headers["Referrer-Policy"] = (
        "strict-origin-when-cross-origin"
    )
    return response

app.include_router(
    accounts.router, prefix="/api/v1"
)
app.include_router(
    scans.router, prefix="/api/v1"
)
app.include_router(
    violations.router, prefix="/api/v1"
)
app.include_router(
    compliance.router, prefix="/api/v1"
)
app.include_router(
    executive.router, prefix="/api/v1"
)
app.include_router(
    drift.router, prefix="/api/v1"
)
app.include_router(
    risk.router, prefix="/api/v1"
)
app.include_router(
    policies.router, prefix="/api/v1"
)
app.include_router(
    iam_graph.router, prefix="/api/v1"
)
app.include_router(
    inventory.router, prefix="/api/v1"
)
app.include_router(
    security_graph.router, prefix="/api/v1"
)
app.include_router(
    jira.router, prefix="/api/v1"
)
app.include_router(websocket.router)


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "cloudline-backend",
        "version": settings.app_version,
    }


# --- Serve built frontend (npm run build) ---
# Must be registered AFTER all API routes.
# Local dev: main.py → app/ → backend/ → repo_root/frontend/dist
# Docker:    main.py → app/ → /app/frontend/dist (volume mount)
_repo_root = Path(__file__).resolve().parent.parent.parent
_frontend_dist = next(
    (
        p
        for p in [
            _repo_root / "frontend" / "dist",
            Path(__file__).resolve().parent.parent
            / "frontend" / "dist",
        ]
        if p.is_dir()
    ),
    _repo_root / "frontend" / "dist",
)

if _frontend_dist.is_dir():
    app.mount(
        "/assets",
        StaticFiles(directory=_frontend_dist / "assets"),
        name="static-assets",
    )

    @app.get("/{full_path:path}")
    async def spa_fallback(
        full_path: str, request: Request
    ):
        """Serve index.html for any non-API route (SPA)."""
        if full_path.startswith("api/"):
            return Response(
                content='{"detail":"Not Found"}',
                status_code=404,
                media_type="application/json",
            )
        file = _frontend_dist / full_path
        if file.is_file():
            return FileResponse(file)
        return FileResponse(
            _frontend_dist / "index.html"
        )
