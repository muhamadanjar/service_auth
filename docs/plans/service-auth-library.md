# Python Service Auth Library Plan

Execution Progress: [Python Service Auth Library Progress](../progress/service-auth-library.md)

Master Plan: [Service Principal OAuth Authorization](../../../../services/usermanagement_api/docs/plans/service-principal-oauth-authorization.md)

## Objective

Provide one versioned implementation of OAuth client-credentials acquisition, online introspection, audience/permission enforcement, FastAPI integration, error mapping, and redaction for internal Python services.

## Contract

- Service tokens use `Authorization: Bearer <service-token>`.
- Delegated user JWTs use `X-User-Authorization: Bearer <internal-user-jwt>` while the service token remains in `Authorization`.
- Token acquisition is cached in memory with single-flight renewal.
- Introspection is performed online for every request without a positive cache.
- Authentication, permission, and authorization-service failures map to `401`, `403`, and `503` respectively.

## Observability

- Emit structured, secret-safe authentication and authorization events.
- Allow each service to register one optional in-process event sink for native
  metrics/tracing integration without coupling this internal library to a
  specific observability vendor.
- Sink failures must never change an authentication or authorization outcome.
- Redaction must recurse through nested mappings and sequences.

## Definition of Done

- Token renewal, concurrency, introspection, audience/scope enforcement, retries, and redaction are covered by tests.
- FastAPI consumers can install the package without copying security logic.
