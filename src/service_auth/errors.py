class ServiceAuthError(RuntimeError):
    """Base error whose message never contains credentials or access tokens."""


class AuthenticationFailed(ServiceAuthError):
    pass


class PermissionDenied(ServiceAuthError):
    pass


class AuthorizationServiceUnavailable(ServiceAuthError):
    pass
