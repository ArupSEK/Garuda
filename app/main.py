"""FastAPI application entrypoint."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app import __version__
from app.api import assets, auth, engagements, findings, reports, scans
from app.config import get_settings
from app.core.logging import configure_logging
from app.database import initialize_database


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)
    initialize_database()
    yield


app = FastAPI(title="External Network VA Scanner", version=__version__, lifespan=lifespan)
for router in (auth.router, engagements.router, scans.router, assets.router, findings.router, reports.router):
    app.include_router(router)


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "service": "external-network-va-scanner", "version": __version__}


@app.exception_handler(Exception)
async def unexpected_error(_: Request, __: Exception) -> JSONResponse:
    return JSONResponse({"detail": "An unexpected server error occurred"}, status_code=500)
