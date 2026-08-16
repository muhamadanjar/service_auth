from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any


logger = logging.getLogger("service_auth.events")


def record_auth_event(event: str, **fields: Any) -> None:
    """Emit a secret-safe structured event suitable for log-based metrics."""
    safe_fields: Mapping[str, Any] = {
        key: value
        for key, value in fields.items()
        if key not in {"access_token", "client_secret", "token"}
    }
    logger.info(
        "service_auth_event event=%s fields=%s",
        event,
        dict(safe_fields),
        extra={"service_auth_event": event, "service_auth_fields": dict(safe_fields)},
    )
