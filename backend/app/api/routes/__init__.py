from fastapi import APIRouter

from app.api.routes.alerts import router as alerts_router
from app.api.routes.assets import router as assets_router
from app.api.routes.audit_logs import router as audit_logs_router
from app.api.routes.auth import router as auth_router
from app.api.routes.discovery import router as discovery_router
from app.api.routes.findings import router as findings_router
from app.api.routes.reports import router as reports_router
from app.api.routes.scans import router as scans_router
from app.api.routes.users import router as users_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(users_router)
api_router.include_router(assets_router)
api_router.include_router(scans_router)
api_router.include_router(reports_router)
api_router.include_router(audit_logs_router)
api_router.include_router(findings_router)
api_router.include_router(discovery_router)
api_router.include_router(alerts_router)
