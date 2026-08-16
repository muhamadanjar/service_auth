from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .errors import AuthenticationFailed, AuthorizationServiceUnavailable, PermissionDenied
from .introspection import OAuthIntrospectionClient
from .models import ServicePrincipal


_service_bearer = HTTPBearer(auto_error=False)


def build_service_principal_dependency(
    introspector: OAuthIntrospectionClient,
    *required_permissions: str,
) -> Callable:
    required = frozenset(required_permissions)

    async def dependency(
        credentials: HTTPAuthorizationCredentials | None = Depends(_service_bearer),
    ) -> ServicePrincipal:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Service access token required",
            )
        try:
            return await introspector.authenticate(credentials.credentials, required)
        except AuthenticationFailed as exc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
        except PermissionDenied as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
        except AuthorizationServiceUnavailable as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc

    return dependency


def parse_delegated_user_token(
    authorization: str | None = Header(default=None, alias="X-User-Authorization"),
) -> str:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Delegated user access token required",
        )
    return token
