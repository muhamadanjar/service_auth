Related Plan: [Python Service Auth Library](../plans/service-auth-library.md)

Execution Progress: [Python Service Auth Library Progress](../progress/service-auth-library.md)

# Python Service Auth Library

`base-project-service-auth` is the shared contract for machine-to-machine HTTP authentication between Python services.

The package lives in `libs/service_auth/` — the standard monorepo location for shared libraries. Service requirements use `-e ../libs/service_auth[test]` for local development. For deployed environments, install via git+ssh:

```bash
pip install "base-project-service-auth @ git+ssh://git@github.com/anjar/base-project-apps.git@main#subdirectory=libs/service_auth"
```

## Caller usage

Use `OAuthServiceClient` in async API code and `SyncOAuthServiceClient` in synchronous workers. Both request `client_credentials` tokens for exactly one audience and a fixed permission set, keep the token only in process memory, and renew it once fewer than 60 seconds remain.

```python
from service_auth import OAuthServiceClient

oauth = OAuthServiceClient(
    "http://usermanagement:8000/oauth/token",
    client_id,
    client_secret,
    "upload-api",
    ("upload.artifacts.read",),
)
headers = await oauth.authorization_header()
```

The token client performs one bounded retry for a transient network or `5xx` failure. It rejects a token response whose audience, scope, expiry, or token value does not match the request.

## Resource-server usage

`OAuthIntrospectionClient` introspects every request online and intentionally has no positive cache. `build_service_principal_dependency` maps invalid credentials to `401`, missing permission to `403`, and an unavailable identity service to `503`.

```python
principal = Depends(
    build_service_principal_dependency(
        introspector,
        "upload.artifacts.read",
    )
)
```

The resulting `ServicePrincipal` contains `client_id`, stable `service_name`, `audience`, permissions, and expiry. Tokens and client secrets are private fields and never included in library errors.

Token acquisition, introspection, authorization denial, and legacy-token compatibility emit structured `service_auth.events` records. These records contain client/audience/outcome metadata only and can be converted into log-based counters and latency alerts.

Services that use native metrics or tracing can register one process-local sink:

```python
from service_auth import set_auth_event_sink

set_auth_event_sink(
    lambda event, fields: auth_counter.labels(
        event=event,
        outcome=str(fields.get("outcome", "unknown")),
    ).inc()
)
```

Credential-like fields are removed recursively before logging or invoking the
sink. Sink exceptions are reduced to a generic warning and never alter the auth
decision. Call `set_auth_event_sink(None)` to detach it during shutdown or tests.

## Delegated user requests

The service identity remains in `Authorization: Bearer <service-token>`. An internal user JWT is carried separately as `X-User-Authorization: Bearer <user-jwt>` and parsed with `parse_delegated_user_token`. The resource route must authorize both identities independently.
