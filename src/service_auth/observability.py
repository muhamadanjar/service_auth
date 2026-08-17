from __future__ import annotations

import logging
import threading
from collections.abc import Mapping
from typing import Any, Callable, TypeAlias


logger = logging.getLogger("service_auth.events")

AuthEventSink: TypeAlias = Callable[[str, Mapping[str, Any]], None]

_SENSITIVE_KEY_PARTS = (
    "authorization",
    "credential",
    "password",
    "secret",
    "token",
)
_sink_lock = threading.RLock()
_event_sink: AuthEventSink | None = None


def _is_sensitive_key(key: object) -> bool:
    normalized = str(key).lower().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _redact(item)
            for key, item in value.items()
            if not _is_sensitive_key(key)
        }
    if isinstance(value, tuple):
        return tuple(_redact(item) for item in value)
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, set):
        return {_redact(item) for item in value}
    return value


def set_auth_event_sink(sink: AuthEventSink | None) -> AuthEventSink | None:
    """Install one optional metrics/tracing sink and return the previous sink."""
    global _event_sink
    with _sink_lock:
        previous = _event_sink
        _event_sink = sink
        return previous


def record_auth_event(event: str, **fields: Any) -> None:
    """Emit a secret-safe structured event to logging and the optional sink."""
    safe_fields: Mapping[str, Any] = _redact(fields)
    logger.info(
        "service_auth_event event=%s fields=%s",
        event,
        dict(safe_fields),
        extra={"service_auth_event": event, "service_auth_fields": dict(safe_fields)},
    )
    with _sink_lock:
        sink = _event_sink
    if sink is not None:
        try:
            sink(event, safe_fields)
        except Exception:
            # Observability must never change an authentication decision. Avoid
            # logging the sink exception because its message may contain secrets.
            logger.warning("service_auth_event_sink_failed event=%s", event)
