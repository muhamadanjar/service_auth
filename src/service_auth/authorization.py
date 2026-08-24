from __future__ import annotations

import asyncio

import httpx

from .errors import AuthorizationServiceUnavailable
from .observability import record_auth_event


class AuthorizationClient:
    """Ask UserManagement for a single permission decision for a user token.

    The caller forwards the end-user's bearer token; UserManagement re-verifies
    it and returns one boolean decision. Intentionally no cache here — the
    calling service owns any caching so role/permission changes are bounded by
    its own TTL, not by this client.
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 5.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.authorize_url = f"{base_url.rstrip('/')}/auth/authorize"
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)
        self._owns_client = client is None

    async def authorize(self, user_token: str, permission: str) -> bool:
        """Return whether the user behind ``user_token`` holds ``permission``.

        Raises AuthorizationServiceUnavailable on transport failure, a 5xx, a
        non-200, or an unparseable response. A ``False`` decision is normal and
        returned as ``False`` (the caller enforces the 403).
        """
        response: httpx.Response | None = None
        for attempt in range(2):
            try:
                response = await self._client.post(
                    self.authorize_url,
                    json={"permission": permission},
                    headers={"Authorization": f"Bearer {user_token}"},
                )
                if response.status_code < 500:
                    break
            except httpx.RequestError:
                if attempt:
                    record_auth_event(
                        "authorize", outcome="unavailable", permission=permission
                    )
                    raise AuthorizationServiceUnavailable(
                        "Authorization service unavailable"
                    ) from None
            await asyncio.sleep(0)
        if response is None or response.status_code >= 500:
            record_auth_event("authorize", outcome="unavailable", permission=permission)
            raise AuthorizationServiceUnavailable("Authorization service unavailable")
        if response.status_code != 200:
            record_auth_event(
                "authorize",
                outcome="rejected",
                permission=permission,
                status_code=response.status_code,
            )
            raise AuthorizationServiceUnavailable("Authorization request rejected")
        try:
            payload = response.json()
        except ValueError as exc:
            record_auth_event("authorize", outcome="invalid_response", permission=permission)
            raise AuthorizationServiceUnavailable(
                "Invalid authorization response"
            ) from exc
        decision = payload.get("data") or {}
        if not payload.get("success") or "allowed" not in decision:
            record_auth_event("authorize", outcome="invalid_response", permission=permission)
            raise AuthorizationServiceUnavailable("Invalid authorization response")
        allowed = bool(decision["allowed"])
        record_auth_event(
            "authorize",
            outcome="allowed" if allowed else "denied",
            permission=permission,
        )
        return allowed

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
