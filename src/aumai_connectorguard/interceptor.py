"""Request interception middleware for aumai-connectorguard."""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, TypeVar, cast

from aumai_connectorguard.core import AuditLog, ConnectionValidator
from aumai_connectorguard.models import AuditEntry, ConnectionAttempt, ConnectionResult

# Generic callable type for wrapping.
_F = TypeVar("_F", bound=Callable[..., Any])


class RequestInterceptor:
    """Middleware that intercepts tool-call requests and validates them.

    Wraps any callable (a tool function) so that every invocation is:

    1. Validated via :class:`~aumai_connectorguard.core.ConnectionValidator`.
    2. Logged to an :class:`~aumai_connectorguard.core.AuditLog`.
    3. Rejected (raises :class:`InterceptorError`) when validation fails.

    Example::

        registry = ConnectorRegistry()
        registry.register(ConnectorSchema(name="my-tool", version="1.0"))
        validator = ConnectionValidator(registry)
        interceptor = RequestInterceptor(validator, audit_log)

        @interceptor.wrap(connector_name="my-tool", source_agent="agent-1")
        def my_tool(x: int) -> int:
            return x * 2

        result = my_tool(x=21)  # validates + executes + logs
    """

    def __init__(
        self,
        validator: ConnectionValidator,
        audit_log: AuditLog | None = None,
    ) -> None:
        self._validator = validator
        self._audit_log = audit_log if audit_log is not None else AuditLog()

    @property
    def audit_log(self) -> AuditLog:
        """Access the audit log associated with this interceptor."""
        return self._audit_log

    def wrap(
        self,
        connector_name: str,
        source_agent: str = "unknown",
    ) -> Callable[[_F], _F]:
        """Decorator factory: wrap *fn* with pre-call validation and audit logging.

        Args:
            connector_name: The name of the connector this callable implements.
            source_agent: The agent identifier making the call.

        Returns:
            A decorator that, when applied, returns a wrapped version of the
            original callable.

        Raises:
            :class:`InterceptorError`: When a call is made and validation denies it.
        """

        def decorator(fn: _F) -> _F:
            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
                input_data = _args_to_dict(args, kwargs)
                attempt = ConnectionAttempt(
                    connector_name=connector_name,
                    input_data=input_data,
                    source_agent=source_agent,
                )

                result = self._validator.validate(attempt)

                self._audit_log.append(
                    AuditEntry(connection_attempt=attempt, result=result)
                )

                if not result.allowed:
                    raise InterceptorError(
                        f"connection to '{connector_name}' denied: {result.reason}"
                    )

                return fn(*args, **kwargs)

            return cast(_F, wrapper)

        return decorator

    def intercept(
        self,
        connector_name: str,
        input_data: dict[str, Any],
        source_agent: str = "unknown",
    ) -> ConnectionResult:
        """Manually intercept a call without executing any underlying function.

        Useful when you have already dispatched the call but want to record
        and validate the metadata.

        Args:
            connector_name: The target connector name.
            input_data: The payload sent to the connector.
            source_agent: The calling agent identifier.

        Returns:
            :class:`~aumai_connectorguard.models.ConnectionResult`.
        """
        attempt = ConnectionAttempt(
            connector_name=connector_name,
            input_data=input_data,
            source_agent=source_agent,
        )
        result = self._validator.validate(attempt)
        self._audit_log.append(AuditEntry(connection_attempt=attempt, result=result))
        return result


class InterceptorError(Exception):
    """Raised when a tool call is rejected by the interceptor."""


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _args_to_dict(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    """Combine positional and keyword arguments into a single dict.

    Positional arguments are stored under the keys ``"arg_0"``, ``"arg_1"``,
    etc. to produce a JSON-serializable snapshot.
    """
    data: dict[str, Any] = {f"arg_{i}": v for i, v in enumerate(args)}
    data.update(kwargs)
    return data


__all__ = ["InterceptorError", "RequestInterceptor"]
