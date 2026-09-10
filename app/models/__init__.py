"""Import every model module so Base.metadata is fully populated for
Alembic autogeneration and for create_all() in tests.
"""
from app.models.organization import Organization  # noqa: F401
from app.models.rbac import Role, Permission  # noqa: F401
from app.models.user import User, EmailVerificationToken, RefreshToken  # noqa: F401
from app.models.case import Mailbox, Case, CaseStatusHistory, Note, Tag, CaseTag  # noqa: F401
from app.models.evidence import EvidenceObject, EvidenceHash, RetentionPolicy  # noqa: F401
from app.models.email import (  # noqa: F401
    EmailMessage,
    EmailHeader,
    ReceivedHop,
    SenderIdentity,
    AuthenticationResult,
)
from app.models.ioc import (  # noqa: F401
    Domain,
    IPAddress,
    URLRecord,
    Attachment,
    IOCRecord,
    ThreatIntelligenceObservation,
)
from app.models.analysis import (  # noqa: F401
    AnalysisRun,
    AnalysisFinding,
    ModelPrediction,
    RiskScore,
)
from app.models.campaign import (  # noqa: F401
    Campaign,
    CampaignMembership,
    GraphEntity,
    GraphRelationship,
)
from app.models.alert import (  # noqa: F401
    Alert,
    ReportTemplate,
    Report,
    AuditLog,
    ApiKey,
    NotificationEvent,
)
