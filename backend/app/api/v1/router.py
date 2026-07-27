from fastapi import APIRouter

from app.api.v1.auth import router as auth_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.sessions import router as sessions_router
from app.api.v1.threats import router as threats_router
from app.api.v1.assessment import router as assessment_router
from app.api.v1.copilot import router as copilot_router
from app.api.v1.uba import router as uba_router
from app.api.v1.simulator import router as simulator_router
from app.api.v1.compliance import router as compliance_router
from app.api.v1.passkeys import router as passkeys_router
from app.api.v1.integrations import router as integrations_router
from app.api.v1.security_actions import router as security_actions_router

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth_router)
api_router.include_router(dashboard_router)
api_router.include_router(sessions_router)
api_router.include_router(threats_router)
api_router.include_router(assessment_router)
api_router.include_router(copilot_router)
api_router.include_router(uba_router)
api_router.include_router(simulator_router)
api_router.include_router(compliance_router)
api_router.include_router(passkeys_router)
api_router.include_router(integrations_router)
api_router.include_router(security_actions_router)
