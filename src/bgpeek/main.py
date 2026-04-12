"""bgpeek FastAPI application entry point."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from bgpeek import __version__
from bgpeek.api import auth as auth_api
from bgpeek.api import devices as devices_api
from bgpeek.api import query as query_api
from bgpeek.config import settings
from bgpeek.core.redis import close_redis, init_redis
from bgpeek.db import devices as device_crud
from bgpeek.db.pool import close_pool, get_pool, init_pool

log = structlog.get_logger()

templates = Jinja2Templates(directory=str(settings.templates_dir))


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Application startup and shutdown hooks."""
    log.info("bgpeek starting", version=__version__, host=settings.host, port=settings.port)
    await init_pool(settings.database_url)
    try:
        await init_redis(settings.redis_url)
    except Exception:
        log.warning("redis unavailable — cache disabled", exc_info=True)
    yield
    await close_redis()
    await close_pool()
    log.info("bgpeek shutting down")


app = FastAPI(
    title="bgpeek",
    description="Open-source looking glass for ISPs and IX operators",
    version=__version__,
    lifespan=lifespan,
)

app.mount(
    "/static",
    StaticFiles(directory=str(settings.static_dir)),
    name="static",
)

app.include_router(auth_api.router)
app.include_router(devices_api.router)
app.include_router(query_api.router)


@app.get("/api/health", response_class=JSONResponse)
async def health() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok", "version": __version__}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    """Main looking glass form — loads devices from DB for the dropdown."""
    try:
        devices = await device_crud.list_devices(get_pool(), enabled_only=True)
    except RuntimeError:
        devices = []
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"version": __version__, "devices": devices},
    )


def run() -> None:
    """Console entry point: start uvicorn."""
    import uvicorn

    uvicorn.run(
        "bgpeek.main:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        log_config=None,
    )


if __name__ == "__main__":
    run()
