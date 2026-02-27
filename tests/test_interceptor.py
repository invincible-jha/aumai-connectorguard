"""Tests for aumai_connectorguard.interceptor."""

from __future__ import annotations

import threading

import pytest

from aumai_connectorguard.core import AuditLog, ConnectionValidator, ConnectorRegistry
from aumai_connectorguard.interceptor import (
    InterceptorError,
    RequestInterceptor,
    _args_to_dict,
)
from aumai_connectorguard.models import AuditEntry, ConnectorSchema
from aumai_connectorguard.rate_limiter import SlidingWindowRateLimiter

# ---------------------------------------------------------------------------
# Helpers shared across tests
# ---------------------------------------------------------------------------


def _make_registry(*schemas: ConnectorSchema) -> ConnectorRegistry:
    registry = ConnectorRegistry()
    for schema in schemas:
        registry.register(schema)
    return registry


def _make_interceptor(
    registry: ConnectorRegistry,
    agent_permissions: dict[str, list[str]] | None = None,
) -> RequestInterceptor:
    """Create a RequestInterceptor with a fresh rate-limiter and no injected audit log.

    Tests that need to inspect the audit log must access it via
    ``interceptor.audit_log`` — the internal AuditLog created by the
    interceptor itself.
    """
    limiter = SlidingWindowRateLimiter()
    validator = ConnectionValidator(
        registry=registry,
        rate_limiter=limiter,
        agent_permissions=agent_permissions or {},
    )
    return RequestInterceptor(validator=validator)


def _make_interceptor_with_log(
    registry: ConnectorRegistry,
    agent_permissions: dict[str, list[str]] | None = None,
) -> tuple[RequestInterceptor, AuditLog]:
    """Return an interceptor and its internal AuditLog together."""
    interceptor = _make_interceptor(registry, agent_permissions)
    return interceptor, interceptor.audit_log


# ---------------------------------------------------------------------------
# _args_to_dict (private helper)
# ---------------------------------------------------------------------------


class TestArgsToDict:
    def test_empty_args_and_kwargs(self) -> None:
        assert _args_to_dict((), {}) == {}

    def test_positional_args_keyed_by_index(self) -> None:
        result = _args_to_dict((10, "hello", True), {})
        assert result == {"arg_0": 10, "arg_1": "hello", "arg_2": True}

    def test_kwargs_merged_in(self) -> None:
        result = _args_to_dict((), {"x": 1, "y": 2})
        assert result == {"x": 1, "y": 2}

    def test_mixed_positional_and_kwargs(self) -> None:
        result = _args_to_dict((42,), {"name": "Alice"})
        assert result == {"arg_0": 42, "name": "Alice"}

    def test_kwarg_overwrites_positional_key(self) -> None:
        # If someone passes a kwarg named "arg_0", it overwrites the positional entry
        result = _args_to_dict((99,), {"arg_0": "overwritten"})
        assert result["arg_0"] == "overwritten"


# ---------------------------------------------------------------------------
# RequestInterceptor.wrap — happy path
# ---------------------------------------------------------------------------


class TestRequestInterceptorWrap:
    def test_wrapped_function_executes_on_success(self) -> None:
        schema = ConnectorSchema(name="adder", version="1.0")
        interceptor = _make_interceptor(_make_registry(schema))

        @interceptor.wrap(connector_name="adder", source_agent="agent-1")
        def add(x: int, y: int) -> int:
            return x + y

        result = add(3, 4)
        assert result == 7

    def test_wrapped_function_passes_positional_args(self) -> None:
        schema = ConnectorSchema(name="double", version="1.0")
        interceptor = _make_interceptor(_make_registry(schema))

        @interceptor.wrap(connector_name="double", source_agent="agent-1")
        def double(n: int) -> int:
            return n * 2

        assert double(21) == 42

    def test_wrapped_function_passes_kwargs(self) -> None:
        schema = ConnectorSchema(name="greeter", version="1.0")
        interceptor = _make_interceptor(_make_registry(schema))

        @interceptor.wrap(connector_name="greeter", source_agent="agent-1")
        def greet(name: str, greeting: str = "Hello") -> str:
            return f"{greeting}, {name}!"

        assert greet(name="World") == "Hello, World!"

    def test_functools_wraps_preserves_metadata(self) -> None:
        schema = ConnectorSchema(name="documented", version="1.0")
        interceptor = _make_interceptor(_make_registry(schema))

        @interceptor.wrap(connector_name="documented", source_agent="agent-1")
        def documented_fn() -> None:
            """My docstring."""

        assert documented_fn.__name__ == "documented_fn"
        assert documented_fn.__doc__ == "My docstring."

    def test_wrapped_function_logs_to_audit_on_allow(self) -> None:
        schema = ConnectorSchema(name="tool", version="1.0")
        interceptor, log = _make_interceptor_with_log(_make_registry(schema))

        @interceptor.wrap(connector_name="tool", source_agent="agent-1")
        def noop() -> None:
            pass

        noop()
        assert len(log) == 1
        entry = log.all_entries()[0]
        assert entry.result.allowed is True

    def test_default_source_agent_is_unknown(self) -> None:
        schema = ConnectorSchema(name="tool", version="1.0")
        interceptor, log = _make_interceptor_with_log(_make_registry(schema))

        @interceptor.wrap(connector_name="tool")
        def noop() -> None:
            pass

        noop()
        entry = log.all_entries()[0]
        assert entry.connection_attempt.source_agent == "unknown"

    def test_audit_log_property_returns_an_audit_log_instance(self) -> None:
        schema = ConnectorSchema(name="tool", version="1.0")
        interceptor = _make_interceptor(_make_registry(schema))
        assert isinstance(interceptor.audit_log, AuditLog)

    def test_audit_log_property_is_stable_across_calls(self) -> None:
        """The same AuditLog object must be returned each time."""
        schema = ConnectorSchema(name="tool", version="1.0")
        interceptor = _make_interceptor(_make_registry(schema))
        assert interceptor.audit_log is interceptor.audit_log

    def test_audit_log_defaults_to_new_instance_when_not_provided(self) -> None:
        schema = ConnectorSchema(name="tool", version="1.0")
        registry = _make_registry(schema)
        limiter = SlidingWindowRateLimiter()
        validator = ConnectionValidator(registry=registry, rate_limiter=limiter)
        interceptor = RequestInterceptor(validator=validator)
        assert isinstance(interceptor.audit_log, AuditLog)

    def test_injected_non_empty_audit_log_is_used(self) -> None:
        """An explicitly injected AuditLog is preserved regardless of its length."""
        schema = ConnectorSchema(name="tool", version="1.0")
        registry = _make_registry(schema)
        limiter = SlidingWindowRateLimiter()
        validator = ConnectionValidator(registry=registry, rate_limiter=limiter)

        pre_populated_log = AuditLog()
        dummy_attempt = __import__(
            "aumai_connectorguard.models", fromlist=["ConnectionAttempt"]
        ).ConnectionAttempt(connector_name="tool")
        dummy_result = __import__(
            "aumai_connectorguard.models", fromlist=["ConnectionResult"]
        ).ConnectionResult(allowed=True)
        pre_populated_log.append(
            AuditEntry(connection_attempt=dummy_attempt, result=dummy_result)
        )

        interceptor = RequestInterceptor(
            validator=validator, audit_log=pre_populated_log
        )
        assert interceptor.audit_log is pre_populated_log
        assert len(interceptor.audit_log) >= 1

    def test_injected_empty_audit_log_is_preserved(self) -> None:
        """An empty AuditLog passed explicitly must not be replaced by a new one.

        This is the direct regression test for CG-M2: the old ``audit_log or
        AuditLog()`` expression discarded a freshly-constructed (falsy) log.
        """
        schema = ConnectorSchema(name="tool", version="1.0")
        registry = _make_registry(schema)
        limiter = SlidingWindowRateLimiter()
        validator = ConnectionValidator(registry=registry, rate_limiter=limiter)

        empty_log = AuditLog()
        interceptor = RequestInterceptor(validator=validator, audit_log=empty_log)
        assert interceptor.audit_log is empty_log


# ---------------------------------------------------------------------------
# RequestInterceptor.wrap — denial and error paths
# ---------------------------------------------------------------------------


class TestRequestInterceptorWrapDenied:
    def test_denied_call_raises_interceptor_error(self) -> None:
        schema = ConnectorSchema(name="tool", version="1.0")
        registry = _make_registry(schema)
        limiter = SlidingWindowRateLimiter()
        validator = ConnectionValidator(registry=registry, rate_limiter=limiter)
        interceptor = RequestInterceptor(validator=validator)

        @interceptor.wrap(
            connector_name="unregistered-connector", source_agent="agent-1"
        )
        def noop() -> None:
            pass

        with pytest.raises(
            InterceptorError, match="connection to 'unregistered-connector' denied"
        ):
            noop()

    def test_interceptor_error_message_contains_reason(self) -> None:
        schema = ConnectorSchema(
            name="secure-tool", version="1.0", required_permissions=["admin:write"]
        )
        registry = _make_registry(schema)
        interceptor = _make_interceptor(registry, agent_permissions={})

        @interceptor.wrap(connector_name="secure-tool", source_agent="agent-1")
        def noop() -> None:
            pass

        with pytest.raises(InterceptorError, match="denied"):
            noop()

    def test_denied_call_still_logs_to_audit(self) -> None:
        schema = ConnectorSchema(
            name="secure-tool", version="1.0", required_permissions=["perm:x"]
        )
        registry = _make_registry(schema)
        interceptor, log = _make_interceptor_with_log(registry, agent_permissions={})

        @interceptor.wrap(connector_name="secure-tool", source_agent="agent-no-perms")
        def noop() -> None:
            pass

        with pytest.raises(InterceptorError):
            noop()

        assert len(log) == 1
        entry = log.all_entries()[0]
        assert entry.result.allowed is False

    def test_underlying_function_not_called_on_denial(self) -> None:
        schema = ConnectorSchema(name="tool", version="1.0")
        registry = _make_registry(schema)
        limiter = SlidingWindowRateLimiter()
        validator = ConnectionValidator(registry=registry, rate_limiter=limiter)
        interceptor = RequestInterceptor(validator=validator)
        called = []

        @interceptor.wrap(connector_name="nonexistent", source_agent="agent-1")
        def side_effect_fn() -> None:
            called.append(True)

        with pytest.raises(InterceptorError):
            side_effect_fn()

        assert called == []

    def test_rate_limit_exceeded_raises_interceptor_error(self) -> None:
        schema = ConnectorSchema(name="rate-tool", version="1.0", rate_limit=2)
        registry = _make_registry(schema)
        limiter = SlidingWindowRateLimiter()
        validator = ConnectionValidator(registry=registry, rate_limiter=limiter)
        interceptor = RequestInterceptor(validator=validator)

        @interceptor.wrap(connector_name="rate-tool", source_agent="agent-1")
        def noop() -> None:
            pass

        noop()
        noop()
        with pytest.raises(InterceptorError):
            noop()


# ---------------------------------------------------------------------------
# RequestInterceptor.intercept — manual interception
# ---------------------------------------------------------------------------


class TestRequestInterceptorIntercept:
    def test_intercept_allowed_connector(self) -> None:
        schema = ConnectorSchema(name="tool", version="1.0")
        interceptor = _make_interceptor(_make_registry(schema))

        result = interceptor.intercept(
            connector_name="tool",
            input_data={"key": "value"},
            source_agent="agent-1",
        )
        assert result.allowed is True

    def test_intercept_logs_the_attempt(self) -> None:
        schema = ConnectorSchema(name="tool", version="1.0")
        interceptor, log = _make_interceptor_with_log(_make_registry(schema))

        interceptor.intercept("tool", {}, "agent-1")
        assert len(log) == 1

    def test_intercept_unregistered_connector_returns_denied(self) -> None:
        interceptor = _make_interceptor(ConnectorRegistry())
        result = interceptor.intercept("ghost-tool", {}, "agent-1")
        assert result.allowed is False

    def test_intercept_uses_default_agent_unknown(self) -> None:
        schema = ConnectorSchema(name="tool", version="1.0")
        interceptor, log = _make_interceptor_with_log(_make_registry(schema))

        interceptor.intercept("tool", {})
        entry = log.all_entries()[0]
        assert entry.connection_attempt.source_agent == "unknown"

    def test_intercept_records_correct_connector_name(self) -> None:
        schema = ConnectorSchema(name="my-connector", version="1.0")
        interceptor, log = _make_interceptor_with_log(_make_registry(schema))

        interceptor.intercept("my-connector", {"x": 1}, "agent-1")
        entry = log.all_entries()[0]
        assert entry.connection_attempt.connector_name == "my-connector"

    def test_intercept_records_input_data(self) -> None:
        schema = ConnectorSchema(name="tool", version="1.0")
        interceptor, log = _make_interceptor_with_log(_make_registry(schema))

        payload = {"temperature": 0.7, "prompt": "Hello"}
        interceptor.intercept("tool", payload, "agent-1")
        entry = log.all_entries()[0]
        assert entry.connection_attempt.input_data == payload

    def test_multiple_intercept_calls_accumulate_in_log(self) -> None:
        schema = ConnectorSchema(name="tool", version="1.0", rate_limit=100)
        interceptor, log = _make_interceptor_with_log(_make_registry(schema))

        for _ in range(5):
            interceptor.intercept("tool", {}, "agent-1")

        assert len(log) == 5

    def test_intercept_permission_denied_returns_correct_result(self) -> None:
        schema = ConnectorSchema(
            name="perm-tool", version="1.0", required_permissions=["special:perm"]
        )
        registry = _make_registry(schema)
        interceptor = _make_interceptor(registry, agent_permissions={})

        result = interceptor.intercept("perm-tool", {}, "agent-no-perms")
        assert result.allowed is False
        assert "missing required permissions" in result.reason

    def test_intercept_denied_is_also_logged(self) -> None:
        schema = ConnectorSchema(
            name="guarded-tool", version="1.0", required_permissions=["x:y"]
        )
        registry = _make_registry(schema)
        interceptor, log = _make_interceptor_with_log(registry, agent_permissions={})

        result = interceptor.intercept("guarded-tool", {}, "unpermitted-agent")
        assert result.allowed is False
        assert len(log) == 1
        assert log.all_entries()[0].result.allowed is False


# ---------------------------------------------------------------------------
# RequestInterceptor — thread safety
# ---------------------------------------------------------------------------


class TestRequestInterceptorThreadSafety:
    def test_concurrent_wraps_log_all_attempts(self) -> None:
        schema = ConnectorSchema(name="concurrent-tool", version="1.0", rate_limit=1000)
        interceptor, log = _make_interceptor_with_log(_make_registry(schema))

        @interceptor.wrap(connector_name="concurrent-tool", source_agent="agent-1")
        def work() -> None:
            pass

        def run_work() -> None:
            for _ in range(10):
                work()

        threads = [threading.Thread(target=run_work) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(log) == 50
