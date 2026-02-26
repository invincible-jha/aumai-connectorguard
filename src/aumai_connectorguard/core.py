"""Core validation logic for aumai-connectorguard."""

from __future__ import annotations

import datetime
import threading
import time
from typing import Any, Callable

import jsonschema

from aumai_connectorguard.models import (
    AuditEntry,
    ConnectorSchema,
    ConnectionAttempt,
    ConnectionResult,
)
from aumai_connectorguard.rate_limiter import SlidingWindowRateLimiter


class RegistryError(Exception):
    """Raised when a connector lookup fails."""


class ConnectorRegistry:
    """Register and look up :class:`~aumai_connectorguard.models.ConnectorSchema` objects.

    Thread-safe.  Connectors are keyed by name; re-registering with the same
    name overwrites the previous schema.

    Example::

        registry = ConnectorRegistry()
        registry.register(ConnectorSchema(name="openai-chat", version="1.0"))
        schema = registry.get("openai-chat")
    """

    def __init__(self) -> None:
        self._schemas: dict[str, ConnectorSchema] = {}
        self._lock = threading.Lock()

    def register(self, schema: ConnectorSchema) -> None:
        """Add or replace a connector schema in the registry."""
        with self._lock:
            self._schemas[schema.name] = schema

    def get(self, name: str) -> ConnectorSchema:
        """Return the schema for *name*.

        Raises:
            RegistryError: If no schema is registered under *name*.
        """
        with self._lock:
            schema = self._schemas.get(name)
        if schema is None:
            raise RegistryError(f"connector '{name}' is not registered")
        return schema

    def all_names(self) -> list[str]:
        """Return a sorted list of all registered connector names."""
        with self._lock:
            return sorted(self._schemas.keys())

    def unregister(self, name: str) -> None:
        """Remove a connector from the registry (no-op if not present)."""
        with self._lock:
            self._schemas.pop(name, None)


class ConnectionValidator:
    """Validate :class:`~aumai_connectorguard.models.ConnectionAttempt` objects.

    Validation pipeline (in order):

    1. Check whether the connector is registered.
    2. Check that the calling agent holds all required permissions.
    3. Check the per-connector rate limit (sliding window).
    4. Validate ``input_data`` against the connector's ``input_schema`` (JSON
       Schema).

    Any failed step short-circuits with a :class:`ConnectionResult` of
    ``allowed=False`` and a descriptive ``reason``.

    Args:
        registry: The :class:`ConnectorRegistry` to resolve schemas from.
        rate_limiter: :class:`~aumai_connectorguard.rate_limiter.SlidingWindowRateLimiter`
                      used for rate-limit enforcement.
        agent_permissions: Map of agent identifier to their permission tokens.
                           An agent not in the map is treated as having no
                           permissions.
        rate_limit_window_seconds: Sliding window size (default 60 s).
    """

    def __init__(
        self,
        registry: ConnectorRegistry,
        rate_limiter: SlidingWindowRateLimiter | None = None,
        agent_permissions: dict[str, list[str]] | None = None,
        rate_limit_window_seconds: int = 60,
    ) -> None:
        self._registry = registry
        self._rate_limiter = rate_limiter or SlidingWindowRateLimiter()
        self._agent_permissions: dict[str, list[str]] = agent_permissions or {}
        self._rate_limit_window_seconds = rate_limit_window_seconds

    def validate(self, attempt: ConnectionAttempt) -> ConnectionResult:
        """Validate *attempt* and return a :class:`ConnectionResult`.

        Args:
            attempt: The connection attempt to validate.

        Returns:
            :class:`ConnectionResult` with ``allowed`` set and a human-readable
            ``reason``.
        """
        start = time.monotonic()

        # Step 1: connector must exist.
        try:
            schema = self._registry.get(attempt.connector_name)
        except RegistryError as exc:
            return ConnectionResult(
                allowed=False,
                reason=str(exc),
                latency_ms=_elapsed_ms(start),
            )

        # Step 2: permission check.
        missing = self._missing_permissions(attempt.source_agent, schema.required_permissions)
        if missing:
            return ConnectionResult(
                allowed=False,
                reason=(
                    f"agent '{attempt.source_agent}' is missing required permissions: "
                    f"{', '.join(sorted(missing))}"
                ),
                latency_ms=_elapsed_ms(start),
            )

        # Step 3: rate limit.
        rate_key = f"{attempt.connector_name}:{attempt.source_agent}"
        within_rate = self._rate_limiter.check_rate_limit(
            connector=rate_key,
            window_seconds=self._rate_limit_window_seconds,
            max_requests=schema.rate_limit,
        )
        if not within_rate:
            return ConnectionResult(
                allowed=False,
                reason=(
                    f"rate limit exceeded for connector '{attempt.connector_name}' "
                    f"(limit: {schema.rate_limit} req/{self._rate_limit_window_seconds}s)"
                ),
                latency_ms=_elapsed_ms(start),
            )

        # Step 4: JSON Schema input validation.
        if schema.input_schema:
            validation_error = _validate_json_schema(attempt.input_data, schema.input_schema)
            if validation_error is not None:
                return ConnectionResult(
                    allowed=False,
                    reason=f"input validation failed: {validation_error}",
                    latency_ms=_elapsed_ms(start),
                )

        return ConnectionResult(
            allowed=True,
            reason="all checks passed",
            latency_ms=_elapsed_ms(start),
        )

    def grant_permission(self, agent: str, permission: str) -> None:
        """Add a permission token to an agent's allow-list."""
        if agent not in self._agent_permissions:
            self._agent_permissions[agent] = []
        if permission not in self._agent_permissions[agent]:
            self._agent_permissions[agent].append(permission)

    def revoke_permission(self, agent: str, permission: str) -> None:
        """Remove a permission token from an agent's allow-list."""
        if agent in self._agent_permissions:
            try:
                self._agent_permissions[agent].remove(permission)
            except ValueError:
                pass

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _missing_permissions(
        self, agent: str, required: list[str]
    ) -> set[str]:
        held = set(self._agent_permissions.get(agent, []))
        return set(required) - held


class AuditLog:
    """Append-only, thread-safe log of all connection attempts and results.

    Example::

        log = AuditLog()
        entry = AuditEntry(connection_attempt=attempt, result=result)
        log.append(entry)
        recent = log.since(datetime.datetime.now(datetime.timezone.utc)
                           - datetime.timedelta(hours=1))
    """

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []
        self._lock = threading.Lock()

    def append(self, entry: AuditEntry) -> None:
        """Add *entry* to the log."""
        with self._lock:
            self._entries.append(entry)

    def all_entries(self) -> list[AuditEntry]:
        """Return a snapshot of all entries (oldest first)."""
        with self._lock:
            return list(self._entries)

    def since(self, cutoff: datetime.datetime) -> list[AuditEntry]:
        """Return entries whose timestamp is >= *cutoff*."""
        with self._lock:
            return [e for e in self._entries if e.timestamp >= cutoff]

    def for_connector(self, connector_name: str) -> list[AuditEntry]:
        """Return all entries for a specific connector."""
        with self._lock:
            return [
                e
                for e in self._entries
                if e.connection_attempt.connector_name == connector_name
            ]

    def for_agent(self, agent: str) -> list[AuditEntry]:
        """Return all entries for a specific agent."""
        with self._lock:
            return [
                e
                for e in self._entries
                if e.connection_attempt.source_agent == agent
            ]

    def denied_entries(self) -> list[AuditEntry]:
        """Return all entries where the connection was denied."""
        with self._lock:
            return [e for e in self._entries if not e.result.allowed]

    def clear(self) -> None:
        """Remove all entries (useful in testing)."""
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _elapsed_ms(start: float) -> float:
    return round((time.monotonic() - start) * 1000, 3)


def _validate_json_schema(data: dict[str, Any], schema: dict[str, Any]) -> str | None:
    """Validate *data* against *schema* using jsonschema.

    Returns:
        An error message string, or ``None`` when validation passes.
    """
    try:
        jsonschema.validate(instance=data, schema=schema)
        return None
    except jsonschema.ValidationError as exc:
        return str(exc.message)
    except jsonschema.SchemaError as exc:
        return f"invalid connector schema definition: {exc.message!s}"


__all__ = [
    "AuditLog",
    "ConnectorRegistry",
    "ConnectionValidator",
    "RegistryError",
]
