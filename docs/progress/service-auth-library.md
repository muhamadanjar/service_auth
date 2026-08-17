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
- [x] Verify editable internal-package installation in each service container build.
- [x] Add structured outcome/legacy-usage observability hooks.
- [x] Add a vendor-neutral metrics/tracing sink with recursive secret redaction.

The package lives in `libs/service_auth/` (monorepo shared library location).

**Installation strategy:**
- Local development: `pip install -e ../libs/service_auth[test]` (path editable)
- Deployed environments: `pip install "base-project-service-auth @ git+ssh://...#subdirectory=libs/service_auth"`
- Future: publish to private PyPI when needed

Upload, ETL, Tileserver, and Payment services reference the package via editable
path install. For container builds, the package is installed from the monorepo
source at build time.
