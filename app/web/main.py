from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import db
from app.config import get_settings
from app.web import routes_explore, routes_fleet, routes_admin, routes_auth, routes_dashboard, routes_events, routes_incidents, routes_intel, routes_insights, routes_cctv, routes_config, routes_logs, routes_site, routes_sitemanager, routes_mail, routes_packs, routes_reports, routes_sources, routes_storage, routes_vpn
from app.web.deps import Redirect, templates


@asynccontextmanager
async def lifespan(_app: FastAPI):
    yield
    await db.dispose()


app = FastAPI(title=get_settings().app_name, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(Path(__file__).resolve().parent.parent / "static")), name="static")

SECURITY_HEADERS = {
    # Charts (ECharts SVG renderer, tooltips) set inline style attributes, so styles allow 'unsafe-inline'.
    # Scripts stay strict: no inline script, no eval.
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
    "frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    if not request.url.path.startswith("/static"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.exception_handler(Redirect)
async def on_redirect(request: Request, exc: Redirect):
    if request.headers.get("hx-request") and not request.headers.get("hx-boosted"):
        return Response(status_code=204, headers={"HX-Redirect": exc.url})
    return RedirectResponse(exc.url, status_code=303)


@app.exception_handler(StarletteHTTPException)
async def on_http_error(request: Request, exc: StarletteHTTPException):
    if request.url.path.startswith("/api/") or request.url.path == "/healthz":
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    return templates.TemplateResponse(
        request, "error.html", {"status": exc.status_code, "detail": exc.detail}, status_code=exc.status_code
    )


@app.get("/healthz", include_in_schema=False)
async def healthz():
    try:
        async with db.engine("web").connect() as conn:
            ts_ver = (await conn.execute(text("SELECT extversion FROM pg_extension WHERE extname='timescaledb'"))).scalar()
    except Exception as e:  # noqa: BLE001 — health must report, not crash
        raise HTTPException(status_code=503, detail=f"database unavailable: {type(e).__name__}")
    return {"status": "ok", "db": "ok", "timescaledb": ts_ver}


app.include_router(routes_auth.router)
app.include_router(routes_dashboard.router)
app.include_router(routes_admin.router)
app.include_router(routes_sources.router)
app.include_router(routes_logs.router)
app.include_router(routes_vpn.router)
app.include_router(routes_explore.router)
app.include_router(routes_fleet.router)
app.include_router(routes_insights.router)
app.include_router(routes_reports.router)
app.include_router(routes_events.router)
app.include_router(routes_incidents.router)
app.include_router(routes_intel.router)
app.include_router(routes_storage.router)
app.include_router(routes_mail.router)
app.include_router(routes_sitemanager.router)
app.include_router(routes_packs.router)
app.include_router(routes_cctv.router)
app.include_router(routes_site.router)
app.include_router(routes_config.router)
