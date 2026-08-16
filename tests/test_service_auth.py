import asyncio

import httpx
import pytest

from service_auth.client import OAuthServiceClient, SyncOAuthServiceClient
from service_auth.errors import (
    AuthenticationFailed,
    AuthorizationServiceUnavailable,
    PermissionDenied,
)
from service_auth.introspection import OAuthIntrospectionClient


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
