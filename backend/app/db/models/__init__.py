# Import all models here so Alembic can detect them
from app.db.base import Base  # noqa: F401
from app.db.models.user import User  # noqa: F401
from app.db.models.session import UserSession  # noqa: F401
from app.db.models.device import Device  # noqa: F401
from app.db.models.login_history import LoginHistory  # noqa: F401
from app.db.models.threat import Threat, Alert  # noqa: F401
from app.db.models.security import IpBlocklist, SecurityScore, BehaviorProfile  # noqa: F401
from app.db.models.assessment import (  # noqa: F401
    PasswordBreachCheck, UrlScanResult, IpReputationCheck, VulnerabilityScan,
)
from app.db.models.simulation import AttackSimulation, SimulationEvent  # noqa: F401
from app.db.models.compliance import AuditLog, IncidentReport  # noqa: F401
from app.db.models.identity_security import (  # noqa: F401
    PasskeyCredential, NotificationIntegration, IntegrationDelivery,
)
