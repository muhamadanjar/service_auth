Related Plan: [Python Service Auth Library](../plans/service-auth-library.md)

# Python Service Auth Library Progress

## Status

Implemented for the first service rollout.

## Checklist

- [x] Implement typed principals and errors.
- [x] Implement token acquisition with in-memory single-flight renewal.
- [x] Implement no-cache introspection and permission enforcement.
- [x] Implement FastAPI dependency integration and delegated-user header contract.
- [x] Add tests and publish feature documentation.
- [ ] Verify editable internal-package installation in each service container build.
- [ ] Add structured outcome/legacy-usage observability hooks.
