import asyncio

import httpx
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from service_auth.client import OAuthServiceClient, SyncOAuthServiceClient
from service_auth.errors import (
    AuthenticationFailed,
    AuthorizationServiceUnavailable,
    PermissionDenied,
)
from service_auth.introspection import OAuthIntrospectionClient
from service_auth.fastapi import (
    build_service_principal_dependency,
    parse_delegated_user_token,
)
from service_auth.observability import record_auth_event, set_auth_event_sink


@pytest.mark.asyncio
async def test_token_client_single_flight_cache():
    calls = 0

    async def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            json={
                "access_token": "opaque",
                "expires_in": 600,
                "audience": "upload-api",
                "scope": "upload.artifacts.read",
            },
        )

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = OAuthServiceClient(
        "https://identity/oauth/token",
        "etl-api",
        "secret",
        "upload-api",
        ("upload.artifacts.read",),
        client=http,
    )
    assert await asyncio.gather(*[client.access_token() for _ in range(10)]) == ["opaque"] * 10
    assert calls == 1
    await http.aclose()


@pytest.mark.asyncio
async def test_introspection_enforces_audience_and_permission():
    async def handler(request):
        return httpx.Response(
            200,
            json={
                "active": True,
                "client_id": "etl-api",
                "service_name": "etl",
                "scope": "upload.artifacts.read",
                "aud": "upload-api",
                "exp": 2_000_000_000,
            },
        )

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    introspector = OAuthIntrospectionClient(
        "https://identity/oauth/introspect",
        "upload-api",
        "secret",
        "upload-api",
        client=http,
    )
    principal = await introspector.authenticate("opaque", frozenset({"upload.artifacts.read"}))
    assert principal.client_id == "etl-api"
    assert principal.service_name == "etl"
    with pytest.raises(PermissionDenied):
        await introspector.authenticate("opaque", frozenset({"upload.artifacts.lease"}))
    await http.aclose()


@pytest.mark.asyncio
async def test_inactive_token_is_authentication_failure():
    async def handler(request):
        return httpx.Response(200, json={"active": False})

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    introspector = OAuthIntrospectionClient(
        "https://identity/oauth/introspect",
        "upload-api",
        "secret",
        "upload-api",
        client=http,
    )
    with pytest.raises(AuthenticationFailed):
        await introspector.authenticate("revoked")
    await http.aclose()


def test_sync_token_client_caches_token():
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            json={
                "access_token": "sync-opaque",
                "expires_in": 600,
                "audience": "upload-api",
                "scope": "upload.artifacts.read",
            },
        )

    http = httpx.Client(transport=httpx.MockTransport(handler))
    client = SyncOAuthServiceClient(
        "https://identity/oauth/token",
        "tileserver-api",
        "secret",
        "upload-api",
        ("upload.artifacts.read",),
        client=http,
    )
    assert client.access_token() == "sync-opaque"
    assert client.access_token() == "sync-opaque"
    assert calls == 1
    http.close()


@pytest.mark.asyncio
async def test_token_client_rejects_wrong_audience_response():
    async def handler(request):
        return httpx.Response(
            200,
            json={
                "access_token": "opaque",
                "expires_in": 600,
                "audience": "payment-api",
                "scope": "upload.artifacts.read",
            },
        )

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = OAuthServiceClient(
        "https://identity/oauth/token",
        "etl-api",
        "secret",
        "upload-api",
        ("upload.artifacts.read",),
        client=http,
    )
    with pytest.raises(AuthorizationServiceUnavailable):
        await client.access_token()
    await http.aclose()


@pytest.mark.asyncio
async def test_introspection_rejects_expired_active_payload():
    async def handler(request):
        return httpx.Response(
            200,
            json={
                "active": True,
                "client_id": "etl-api",
                "service_name": "etl",
                "scope": "upload.artifacts.read",
                "aud": "upload-api",
                "exp": 1,
            },
        )

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    introspector = OAuthIntrospectionClient(
        "https://identity/oauth/introspect",
        "upload-api",
        "secret",
        "upload-api",
        client=http,
    )
    with pytest.raises(AuthenticationFailed):
        await introspector.authenticate("opaque")
    await http.aclose()


def test_structured_event_redacts_credential_fields(caplog):
    with caplog.at_level("INFO", logger="service_auth.events"):
        record_auth_event(
            "test",
            audience="upload-api",
            access_token="must-not-appear",
            client_secret="must-not-appear-either",
            request={
                "Authorization": "Bearer nested-secret",
                "metadata": {"password": "nested-password", "attempt": 1},
            },
        )
    assert "upload-api" in caplog.text
    assert "must-not-appear" not in caplog.text
    assert "nested-secret" not in caplog.text
    assert "nested-password" not in caplog.text


def test_structured_event_sink_receives_only_safe_fields():
    received = []
    previous = set_auth_event_sink(
        lambda event, fields: received.append((event, dict(fields)))
    )
    try:
        record_auth_event(
            "legacy_static_token",
            service_name="etl-api",
            nested={"client_secret": "hidden", "outcome": "accepted"},
        )
    finally:
        set_auth_event_sink(previous)

    assert received == [
        (
            "legacy_static_token",
            {"service_name": "etl-api", "nested": {"outcome": "accepted"}},
        )
    ]


def test_structured_event_sink_failure_does_not_escape(caplog):
    def failing_sink(_event, _fields):
        raise RuntimeError("must-not-leak-secret")

    previous = set_auth_event_sink(failing_sink)
    try:
        with caplog.at_level("WARNING", logger="service_auth.events"):
            record_auth_event("introspection", outcome="success")
    finally:
        set_auth_event_sink(previous)

    assert "service_auth_event_sink_failed" in caplog.text
    assert "must-not-leak-secret" not in caplog.text


def test_delegated_user_token_uses_separate_header_contract():
    assert parse_delegated_user_token("Bearer internal-user-jwt") == "internal-user-jwt"
    with pytest.raises(HTTPException) as exc:
        parse_delegated_user_token("Basic unsupported")
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_fastapi_dependency_maps_permission_denial_to_403():
    class DenyingIntrospector:
        async def authenticate(self, token, required_permissions):
            raise PermissionDenied("Required service permission is missing")

    dependency = build_service_principal_dependency(
        DenyingIntrospector(), "upload.artifacts.lease"
    )
    with pytest.raises(HTTPException) as exc:
        await dependency(
            HTTPAuthorizationCredentials(scheme="Bearer", credentials="opaque")
        )
    assert exc.value.status_code == 403
