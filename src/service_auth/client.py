from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass
from time import monotonic

import httpx

from .errors import AuthorizationServiceUnavailable
from .observability import record_auth_event


@dataclass(frozen=True)
class ServiceToken:
    access_token: str
    expires_in: int
    audience: str
    scope: str


class OAuthServiceClient:
    """Acquire and retain one short-lived service token per process."""

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        audience: str,
        scopes: tuple[str, ...],
        *,
        refresh_skew_seconds: int = 60,
        timeout_seconds: float = 5.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.token_url = token_url
        self.client_id = client_id
        self._client_secret = client_secret
        self.audience = audience
        self.scopes = scopes
        self.refresh_skew_seconds = refresh_skew_seconds
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)
        self._owns_client = client is None
        self._token: ServiceToken | None = None
        self._refresh_at = 0.0
        self._lock = asyncio.Lock()

    async def access_token(self) -> str:
        if self._token and monotonic() < self._refresh_at:
            return self._token.access_token
        async with self._lock:
            if self._token and monotonic() < self._refresh_at:
                return self._token.access_token
            self._token = await self._acquire()
            self._refresh_at = monotonic() + max(
                0, self._token.expires_in - self.refresh_skew_seconds
            )
            return self._token.access_token

    async def authorization_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {await self.access_token()}"}

    async def _acquire(self) -> ServiceToken:
        data = {
            "grant_type": "client_credentials",
            "audience": self.audience,
            "scope": " ".join(self.scopes),
        }
        response: httpx.Response | None = None
        for attempt in range(2):
            try:
                response = await self._client.post(
                    self.token_url,
                    data=data,
                    auth=httpx.BasicAuth(self.client_id, self._client_secret),
                )
                if response.status_code < 500:
                    break
            except httpx.RequestError:
                if attempt:
                    record_auth_event(
                        "token_acquisition",
                        outcome="unavailable",
                        client_id=self.client_id,
                        audience=self.audience,
                    )
                    raise AuthorizationServiceUnavailable(
                        "OAuth token service unavailable"
                    ) from None
            await asyncio.sleep(0)
        if response is None or response.status_code >= 500:
            record_auth_event(
                "token_acquisition",
                outcome="unavailable",
                client_id=self.client_id,
                audience=self.audience,
            )
            raise AuthorizationServiceUnavailable("OAuth token service unavailable")
        if response.status_code != 200:
            record_auth_event(
                "token_acquisition",
                outcome="rejected",
                client_id=self.client_id,
                audience=self.audience,
                status_code=response.status_code,
            )
            raise AuthorizationServiceUnavailable("OAuth client authentication failed")
        try:
            payload = response.json()
        except ValueError as exc:
            record_auth_event(
                "token_acquisition",
                outcome="invalid_response",
                client_id=self.client_id,
                audience=self.audience,
            )
            raise AuthorizationServiceUnavailable("Invalid OAuth token response") from exc
        try:
            token = ServiceToken(
                access_token=str(payload["access_token"]),
                expires_in=int(payload["expires_in"]),
                audience=str(payload["audience"]),
                scope=str(payload.get("scope") or ""),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthorizationServiceUnavailable("Invalid OAuth token response") from exc
        if (
            not token.access_token
            or token.expires_in <= 0
            or token.audience != self.audience
            or not set(self.scopes).issubset(token.scope.split())
        ):
            record_auth_event(
                "token_acquisition",
                outcome="invalid_response",
                client_id=self.client_id,
                audience=self.audience,
            )
            raise AuthorizationServiceUnavailable("Invalid OAuth token response")
        record_auth_event(
            "token_acquisition",
            outcome="success",
            client_id=self.client_id,
            audience=self.audience,
            expires_in=token.expires_in,
        )
        return token

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


class SyncOAuthServiceClient:
    """Synchronous equivalent for workers and requests-based clients."""

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        audience: str,
        scopes: tuple[str, ...],
        *,
        refresh_skew_seconds: int = 60,
        timeout_seconds: float = 5.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.token_url = token_url
        self.client_id = client_id
        self._client_secret = client_secret
        self.audience = audience
        self.scopes = scopes
        self.refresh_skew_seconds = refresh_skew_seconds
        self._client = client or httpx.Client(timeout=timeout_seconds)
        self._owns_client = client is None
        self._token: ServiceToken | None = None
        self._refresh_at = 0.0
        self._lock = threading.Lock()

    def access_token(self) -> str:
        if self._token and monotonic() < self._refresh_at:
            return self._token.access_token
        with self._lock:
            if self._token and monotonic() < self._refresh_at:
                return self._token.access_token
            self._token = self._acquire()
            self._refresh_at = monotonic() + max(
                0, self._token.expires_in - self.refresh_skew_seconds
            )
            return self._token.access_token

    def authorization_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token()}"}

    def _acquire(self) -> ServiceToken:
        response: httpx.Response | None = None
        for _attempt in range(2):
            try:
                response = self._client.post(
                    self.token_url,
                    data={
                        "grant_type": "client_credentials",
                        "audience": self.audience,
                        "scope": " ".join(self.scopes),
                    },
                    auth=httpx.BasicAuth(self.client_id, self._client_secret),
                )
                if response.status_code < 500:
                    break
            except httpx.RequestError:
                continue
        if response is None or response.status_code >= 500:
            record_auth_event(
                "token_acquisition",
                outcome="unavailable",
                client_id=self.client_id,
                audience=self.audience,
            )
            raise AuthorizationServiceUnavailable("OAuth token service unavailable")
        if response.status_code != 200:
            record_auth_event(
                "token_acquisition",
                outcome="rejected",
                client_id=self.client_id,
                audience=self.audience,
                status_code=response.status_code,
            )
            raise AuthorizationServiceUnavailable("OAuth client authentication failed")
        try:
            payload = response.json()
        except ValueError as exc:
            record_auth_event(
                "token_acquisition",
                outcome="invalid_response",
                client_id=self.client_id,
                audience=self.audience,
            )
            raise AuthorizationServiceUnavailable("Invalid OAuth token response") from exc
        try:
            token = ServiceToken(
                access_token=str(payload["access_token"]),
                expires_in=int(payload["expires_in"]),
                audience=str(payload["audience"]),
                scope=str(payload.get("scope") or ""),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthorizationServiceUnavailable("Invalid OAuth token response") from exc
        if (
            not token.access_token
            or token.expires_in <= 0
            or token.audience != self.audience
            or not set(self.scopes).issubset(token.scope.split())
        ):
            record_auth_event(
                "token_acquisition",
                outcome="invalid_response",
                client_id=self.client_id,
                audience=self.audience,
            )
            raise AuthorizationServiceUnavailable("Invalid OAuth token response")
        record_auth_event(
            "token_acquisition",
            outcome="success",
            client_id=self.client_id,
            audience=self.audience,
            expires_in=token.expires_in,
        )
        return token

    def close(self) -> None:
        if self._owns_client:
            self._client.close()
