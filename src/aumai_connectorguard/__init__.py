"""AumAI ConnectorGuard — runtime validation for agent-to-tool connections.

Public API::

    from aumai_connectorguard import (
        AuditEntry,
        AuditLog,
        ConnectorRegistry,
        ConnectorSchema,
        ConnectionAttempt,
        ConnectionResult,
        ConnectionValidator,
        InterceptorError,
        RateLimitState,
        RegistryError,
        RequestInterceptor,
        SlidingWindowRateLimiter,
    )
"""

from aumai_connectorguard.core import (
    AuditLog,
    ConnectorRegistry,
    ConnectionValidator,
    RegistryError,
)
from aumai_connectorguard.interceptor import InterceptorError, RequestInterceptor
from aumai_connectorguard.models import (
    AuditEntry,
    ConnectorSchema,
    ConnectionAttempt,
    ConnectionResult,
    RateLimitState,
)
from aumai_connectorguard.rate_limiter import SlidingWindowRateLimiter, check_rate_limit

__version__ = "0.1.0"

__all__ = [
    # models
    "AuditEntry",
    "ConnectorSchema",
    "ConnectionAttempt",
    "ConnectionResult",
    "RateLimitState",
    # core
    "AuditLog",
    "ConnectorRegistry",
    "ConnectionValidator",
    "RegistryError",
    # rate limiter
    "SlidingWindowRateLimiter",
    "check_rate_limit",
    # interceptor
    "InterceptorError",
    "RequestInterceptor",
]
