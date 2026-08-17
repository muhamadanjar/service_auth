# base-project-service-auth

Shared OAuth2 service-principal authentication library for Base Project FastAPI services.

Provides machine-to-machine authentication via OAuth2 client-credentials tokens and introspection — no duplicated security logic across services.

## Installation

### Local development (monorepo)

```bash
# From any service directory
pip install -e ../libs/service_auth
```

### Git+SSH (deploy terpisah / CI)

```bash
pip install "base-project-service-auth @ git+ssh://git@github.com/anjar/base-project-apps.git@main#subdirectory=libs/service_auth"
```

### Specific version

```bash
pip install "base-project-service-auth @ git+ssh://git@github.com/anjar/base-project-apps.git@v0.1.0#subdirectory=libs/service_auth"
```

## Usage

### Caller (service yang memanggil service lain)

```python
from service_auth import OAuthServiceClient, SyncOAuthServiceClient

# Async (FastAPI / async workers)
oauth = OAuthServiceClient(
    "http://usermanagement:8000/oauth/token",
    client_id,
    client_secret,
    "upload-api",
    ("upload.artifacts.read",),
)
headers = await oauth.authorization_header()

# Sync (workers / requests-based)
oauth = SyncOAuthServiceClient(
    "http://usermanagement:8000/oauth/token",
    client_id,
    client_secret,
    "upload-api",
    ("upload.artifacts.read",),
)
headers = oauth.authorization_header()
```

### Resource server (service yang menerima request)

```python
from service_auth import OAuthIntrospectionClient, build_service_principal_dependency

introspector = OAuthIntrospectionClient(
    "http://usermanagement:8000/oauth/introspect",
    client_id,
    client_secret,
    "upload-api",
)

# FastAPI route dependency
principal = Depends(
    build_service_principal_dependency(introspector, "upload.artifacts.read")
)
```

### Observability

```python
from service_auth import set_auth_event_sink

set_auth_event_sink(
    lambda event, fields: auth_counter.labels(
        event=event,
        outcome=str(fields.get("outcome", "unknown")),
    ).inc()
)
```

## Development

```bash
cd libs/service_auth
pip install -e ".[test]"
pytest
```

## License

MIT
