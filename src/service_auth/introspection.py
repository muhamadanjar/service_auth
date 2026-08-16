from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx

from .errors import AuthenticationFailed, AuthorizationServiceUnavailable, PermissionDenied
from .models import ServicePrincipal
from .observability import record_auth_event


class OAuthIntrospectionClient:
    """Validate every opaque service token online; intentionally has no cache."""

    def __init__(
        self,
        introspection_url: str,
        client_id: str,
        client_secret: str,
        audience: str,
        *,
        timeout_seconds: float = 5.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.introspection_url = introspection_url
        self.client_id = client_id
        self._client_secret = client_secret
        self.audience = audience
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)
        self._owns_client = client is None

    async def authenticate(
        self,
        token: str,
        required_permissions: frozenset[str] = frozenset(),
    ) -> ServicePrincipal:
        response: httpx.Response | None = None
        for attempt in range(2):
            try:
                response = await self._client.post(
                    self.introspection_url,
                    data={"token": token, "audience": self.audience},
                    auth=httpx.BasicAuth(self.client_id, self._client_secret),
                )
                if response.status_code < 500:
                    break
            except httpx.RequestError:
                if attempt:
                    record_auth_event(
                        "introspection",
                        outcome="unavailable",
                        client_id=self.client_id,
                        audience=self.audience,
                    )
                    raise AuthorizationServiceUnavailable(
                        "OAuth introspection service unavailable"
                    ) from None
            await asyncio.sleep(0)
        if response is None or response.status_code >= 500:
            record_auth_event(
                "introspection",
                outcome="unavailable",
                client_id=self.client_id,
                audience=self.audience,
            )
            raise AuthorizationServiceUnavailable("OAuth introspection service unavailable")
        if response.status_code != 200:
            record_auth_event(
                "introspection",
                outcome="resource_client_rejected",
                client_id=self.client_id,
                audience=self.audience,
                status_code=response.status_code,
            )
            raise AuthorizationServiceUnavailable("OAuth introspection client rejected")
        try:
            payload = response.json()
        except ValueError as exc:
            record_auth_event(
                "introspection",
                outcome="invalid_response",
                client_id=self.client_id,
                audience=self.audience,
            )
            raise AuthorizationServiceUnavailable(
                "Invalid OAuth introspection response"
            ) from exc
        if not payload.get("active") or payload.get("aud") != self.audience:
            record_auth_event(
                "introspection",
                outcome="invalid_token",
                client_id=self.client_id,
                audience=self.audience,
            )
            raise AuthenticationFailed("Invalid service access token")
        permissions = frozenset(str(payload.get("scope") or "").split())
        missing = required_permissions - permissions
        if missing:
            record_auth_event(
                "authorization",
                outcome="permission_denied",
                client_id=str(payload.get("client_id") or "unknown"),
                audience=self.audience,
                missing_permissions=" ".join(sorted(missing)),
            )
            raise PermissionDenied("Required service permission is missing")
        try:
            expires_at = datetime.fromtimestamp(int(payload["exp"]), timezone.utc)
            client_id = str(payload["client_id"])
            service_name = str(payload["service_name"])
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthenticationFailed("Invalid service access token") from exc
        if (
            expires_at <= datetime.now(timezone.utc)
            or not client_id
            or not service_name
            or service_name == "None"
        ):
            record_auth_event(
                "introspection",
                outcome="invalid_payload",
                client_id=self.client_id,
                audience=self.audience,
            )
            raise AuthenticationFailed("Invalid service access token")
        record_auth_event(
            "introspection",
            outcome="success",
            client_id=client_id,
            service_name=service_name,
            audience=self.audience,
        )
        return ServicePrincipal(
            client_id=client_id,
            service_name=service_name,
            audience=self.audience,
            permissions=permissions,
            expires_at=expires_at,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
