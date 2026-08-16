from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class ServicePrincipal:
    client_id: str
    service_name: str
    audience: str
    permissions: frozenset[str]
    expires_at: datetime
