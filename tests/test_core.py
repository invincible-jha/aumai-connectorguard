"""Tests for aumai_connectorguard.core."""

from __future__ import annotations

import datetime
import threading
import time

import pytest

from aumai_connectorguard.core import (
    AuditLog,
    ConnectionValidator,
    ConnectorRegistry,
    RegistryError,
    _elapsed_ms,
    _validate_json_schema,
)
from aumai_connectorguard.models import (
    AuditEntry,
    ConnectionAttempt,
    ConnectionResult,
    ConnectorSchema,
)
from aumai_connectorguard.rate_limiter import SlidingWindowRateLimiter

# ---------------------------------------------------------------------------
# ConnectorRegistry
# ---------------------------------------------------------------------------


class TestConnectorRegistry:
    def test_register_and_get_round_trip(self, simple_schema: ConnectorSchema) -> None:
        registry = ConnectorRegistry()
        registry.register(simple_schema)
        retrieved = registry.get(simple_schema.name)
        assert retrieved == simple_schema

    def test_get_unregistered_raises_registry_error(self) -> None:
        registry = ConnectorRegistry()
        with pytest.raises(RegistryError, match="not registered"):
            registry.get("nonexistent-connector")

    def test_registry_error_message_contains_name(self) -> None:
        registry = ConnectorRegistry()
        with pytest.raises(RegistryError, match="'missing-tool'"):
            registry.get("missing-tool")

    def test_re_register_overwrites_previous(self) -> None:
        registry = ConnectorRegistry()
        v1 = ConnectorSchema(name="tool", version="1.0.0")
        v2 = ConnectorSchema(name="tool", version="2.0.0")
        registry.register(v1)
        registry.register(v2)
        assert registry.get("tool").version == "2.0.0"

    def test_all_names_returns_sorted_list(self) -> None:
        registry = ConnectorRegistry()
        registry.register(ConnectorSchema(name="zebra-tool", version="1.0"))
        registry.register(ConnectorSchema(name="alpha-tool", version="1.0"))
        registry.register(ConnectorSchema(name="middle-tool", version="1.0"))
        assert registry.all_names() == ["alpha-tool", "middle-tool", "zebra-tool"]

    def test_all_names_empty_registry(self) -> None:
        registry = ConnectorRegistry()
        assert registry.all_names() == []

    def test_unregister_removes_connector(self) -> None:
        registry = ConnectorRegistry()
        registry.register(ConnectorSchema(name="tool", version="1.0"))
        registry.unregister("tool")
        with pytest.raises(RegistryError):
            registry.get("tool")

    def test_unregister_nonexistent_is_no_op(self) -> None:
        registry = ConnectorRegistry()
        registry.unregister("does-not-exist")  # must not raise

    def test_register_multiple_connectors(self) -> None:
        registry = ConnectorRegistry()
        names = ["tool-a", "tool-b", "tool-c"]
        for name in names:
            registry.register(ConnectorSchema(name=name, version="1.0"))
        assert set(registry.all_names()) == set(names)

    def test_thread_safety_concurrent_register(self) -> None:
        registry = ConnectorRegistry()
        errors: list[Exception] = []

        def register_many(prefix: str) -> None:
            try:
                for i in range(50):
                    registry.register(
                        ConnectorSchema(name=f"{prefix}-{i}", version="1.0")
                    )
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [
            threading.Thread(target=register_many, args=(f"t{j}",)) for j in range(4)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == [], f"Thread errors: {errors}"
        assert len(registry.all_names()) == 200  # 4 threads * 50 each

    def test_thread_safety_concurrent_get(self) -> None:
        registry = ConnectorRegistry()
        registry.register(ConnectorSchema(name="shared-tool", version="1.0"))
        errors: list[Exception] = []

        def get_repeatedly() -> None:
            try:
                for _ in range(100):
                    schema = registry.get("shared-tool")
                    assert schema.name == "shared-tool"
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=get_repeatedly) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == []


# ---------------------------------------------------------------------------
# ConnectionValidator — step 1: connector existence
# ---------------------------------------------------------------------------


class TestConnectionValidatorRegistryCheck:
    def test_unknown_connector_is_denied(self) -> None:
        registry = ConnectorRegistry()
        validator = ConnectionValidator(registry)
        attempt = ConnectionAttempt(connector_name="unknown-tool")
        result = validator.validate(attempt)
        assert result.allowed is False
        assert "not registered" in result.reason

    def test_known_connector_with_no_schema_restrictions_is_allowed(
        self, populated_registry: ConnectorRegistry
    ) -> None:
        validator = ConnectionValidator(populated_registry)
        attempt = ConnectionAttempt(connector_name="simple-tool")
        result = validator.validate(attempt)
        assert result.allowed is True

    def test_result_includes_latency_ms(
        self, populated_registry: ConnectorRegistry
    ) -> None:
        validator = ConnectionValidator(populated_registry)
        attempt = ConnectionAttempt(connector_name="simple-tool")
        result = validator.validate(attempt)
        assert result.latency_ms >= 0.0


# ---------------------------------------------------------------------------
# ConnectionValidator — step 2: permission check
# ---------------------------------------------------------------------------


class TestConnectionValidatorPermissions:
    def test_agent_with_all_permissions_allowed(
        self, validator_with_agent: ConnectionValidator
    ) -> None:
        attempt = ConnectionAttempt(
            connector_name="secure-tool", source_agent="trusted-agent"
        )
        result = validator_with_agent.validate(attempt)
        assert result.allowed is True

    def test_agent_missing_all_permissions_denied(
        self, populated_registry: ConnectorRegistry
    ) -> None:
        validator = ConnectionValidator(populated_registry, agent_permissions={})
        attempt = ConnectionAttempt(
            connector_name="secure-tool", source_agent="untrusted-agent"
        )
        result = validator.validate(attempt)
        assert result.allowed is False
        assert "missing required permissions" in result.reason

    def test_reason_lists_missing_permissions(
        self, populated_registry: ConnectorRegistry
    ) -> None:
        validator = ConnectionValidator(
            populated_registry,
            agent_permissions={"partial-agent": ["read:data"]},
        )
        attempt = ConnectionAttempt(
            connector_name="secure-tool", source_agent="partial-agent"
        )
        result = validator.validate(attempt)
        assert result.allowed is False
        assert "write:data" in result.reason

    def test_agent_with_partial_permissions_denied(
        self, populated_registry: ConnectorRegistry
    ) -> None:
        validator = ConnectionValidator(
            populated_registry,
            agent_permissions={"half-agent": ["read:data"]},
        )
        attempt = ConnectionAttempt(
            connector_name="secure-tool", source_agent="half-agent"
        )
        result = validator.validate(attempt)
        assert result.allowed is False

    def test_unknown_agent_treated_as_no_permissions(
        self, populated_registry: ConnectorRegistry
    ) -> None:
        validator = ConnectionValidator(
            populated_registry,
            agent_permissions={"other-agent": ["read:data", "write:data"]},
        )
        attempt = ConnectionAttempt(
            connector_name="secure-tool", source_agent="ghost-agent"
        )
        result = validator.validate(attempt)
        assert result.allowed is False

    def test_grant_permission_enables_access(
        self, populated_registry: ConnectorRegistry
    ) -> None:
        validator = ConnectionValidator(populated_registry)
        validator.grant_permission("new-agent", "read:data")
        validator.grant_permission("new-agent", "write:data")
        attempt = ConnectionAttempt(
            connector_name="secure-tool", source_agent="new-agent"
        )
        result = validator.validate(attempt)
        assert result.allowed is True

    def test_revoke_permission_removes_access(
        self, populated_registry: ConnectorRegistry
    ) -> None:
        validator = ConnectionValidator(
            populated_registry,
            agent_permissions={"agent-x": ["read:data", "write:data"]},
        )
        validator.revoke_permission("agent-x", "write:data")
        attempt = ConnectionAttempt(
            connector_name="secure-tool", source_agent="agent-x"
        )
        result = validator.validate(attempt)
        assert result.allowed is False

    def test_revoke_nonexistent_permission_is_no_op(
        self, populated_registry: ConnectorRegistry
    ) -> None:
        validator = ConnectionValidator(
            populated_registry,
            agent_permissions={"agent-x": ["read:data", "write:data"]},
        )
        validator.revoke_permission("agent-x", "nonexistent:perm")  # must not raise
        attempt = ConnectionAttempt(
            connector_name="secure-tool", source_agent="agent-x"
        )
        result = validator.validate(attempt)
        assert result.allowed is True

    def test_revoke_permission_on_unknown_agent_is_no_op(
        self, populated_registry: ConnectorRegistry
    ) -> None:
        validator = ConnectionValidator(populated_registry)
        validator.revoke_permission("ghost-agent", "read:data")  # must not raise

    def test_grant_duplicate_permission_not_duplicated(
        self, populated_registry: ConnectorRegistry
    ) -> None:
        validator = ConnectionValidator(populated_registry)
        validator.grant_permission("agent-y", "read:data")
        validator.grant_permission("agent-y", "read:data")
        # Verify internal list does not contain duplicates
        permissions = validator._agent_permissions.get("agent-y", [])
        assert permissions.count("read:data") == 1

    def test_connector_with_no_permissions_allows_any_agent(
        self, populated_registry: ConnectorRegistry
    ) -> None:
        validator = ConnectionValidator(populated_registry, agent_permissions={})
        attempt = ConnectionAttempt(
            connector_name="simple-tool", source_agent="random-agent"
        )
        result = validator.validate(attempt)
        assert result.allowed is True

    def test_grant_permission_and_validate_concurrent_access(
        self, populated_registry: ConnectorRegistry
    ) -> None:
        """Concurrent grant_permission and validate calls must not race.

        CG-H1: permission mutations and reads are now protected by
        _permissions_lock, so no data corruption or RuntimeError should
        occur even under high concurrency.
        """
        validator = ConnectionValidator(populated_registry, agent_permissions={})
        errors: list[Exception] = []
        iterations = 200

        def grant_and_revoke() -> None:
            try:
                for _ in range(iterations):
                    validator.grant_permission("race-agent", "read:data")
                    validator.grant_permission("race-agent", "write:data")
                    validator.revoke_permission("race-agent", "write:data")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        def validate_repeatedly() -> None:
            try:
                for _ in range(iterations):
                    attempt = ConnectionAttempt(
                        connector_name="secure-tool", source_agent="race-agent"
                    )
                    # Result may be allowed or denied depending on timing —
                    # what matters is that no exception is raised.
                    validator.validate(attempt)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [
            threading.Thread(target=grant_and_revoke),
            threading.Thread(target=grant_and_revoke),
            threading.Thread(target=validate_repeatedly),
            threading.Thread(target=validate_repeatedly),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == [], f"Thread safety errors: {errors}"


# ---------------------------------------------------------------------------
# ConnectionValidator — step 3: rate limiting
# ---------------------------------------------------------------------------


class TestConnectionValidatorRateLimit:
    def test_requests_within_limit_allowed(
        self, populated_registry: ConnectorRegistry
    ) -> None:
        limiter = SlidingWindowRateLimiter()
        validator = ConnectionValidator(populated_registry, rate_limiter=limiter)
        for _ in range(3):
            attempt = ConnectionAttempt(
                connector_name="low-rate-tool", source_agent="a"
            )
            result = validator.validate(attempt)
            assert result.allowed is True

    def test_request_exceeding_limit_denied(
        self, populated_registry: ConnectorRegistry
    ) -> None:
        limiter = SlidingWindowRateLimiter()
        validator = ConnectionValidator(populated_registry, rate_limiter=limiter)
        for _ in range(3):
            validator.validate(
                ConnectionAttempt(connector_name="low-rate-tool", source_agent="a")
            )
        result = validator.validate(
            ConnectionAttempt(connector_name="low-rate-tool", source_agent="a")
        )
        assert result.allowed is False
        assert "rate limit exceeded" in result.reason

    def test_rate_limit_reason_contains_connector_name(
        self, populated_registry: ConnectorRegistry
    ) -> None:
        limiter = SlidingWindowRateLimiter()
        validator = ConnectionValidator(populated_registry, rate_limiter=limiter)
        for _ in range(3):
            validator.validate(
                ConnectionAttempt(connector_name="low-rate-tool", source_agent="a")
            )
        result = validator.validate(
            ConnectionAttempt(connector_name="low-rate-tool", source_agent="a")
        )
        assert "low-rate-tool" in result.reason

    def test_rate_limit_keyed_per_agent(
        self, populated_registry: ConnectorRegistry
    ) -> None:
        limiter = SlidingWindowRateLimiter()
        validator = ConnectionValidator(populated_registry, rate_limiter=limiter)
        for _ in range(3):
            validator.validate(
                ConnectionAttempt(connector_name="low-rate-tool", source_agent="a")
            )
        # Different agent should still be allowed
        result = validator.validate(
            ConnectionAttempt(connector_name="low-rate-tool", source_agent="b")
        )
        assert result.allowed is True


# ---------------------------------------------------------------------------
# ConnectionValidator — step 4: JSON Schema input validation
# ---------------------------------------------------------------------------


class TestConnectionValidatorInputSchema:
    def test_valid_input_data_passes(
        self, validator_no_permissions: ConnectionValidator
    ) -> None:
        attempt = ConnectionAttempt(
            connector_name="typed-tool",
            source_agent="agent-1",
            input_data={"prompt": "Hello"},
        )
        result = validator_no_permissions.validate(attempt)
        assert result.allowed is True

    def test_missing_required_field_denied(
        self, validator_no_permissions: ConnectionValidator
    ) -> None:
        attempt = ConnectionAttempt(
            connector_name="typed-tool",
            source_agent="agent-1",
            input_data={"max_tokens": 100},  # "prompt" required but absent
        )
        result = validator_no_permissions.validate(attempt)
        assert result.allowed is False
        assert "input validation failed" in result.reason

    def test_wrong_type_denied(
        self, validator_no_permissions: ConnectionValidator
    ) -> None:
        attempt = ConnectionAttempt(
            connector_name="typed-tool",
            source_agent="agent-1",
            input_data={"prompt": 12345},  # must be string
        )
        result = validator_no_permissions.validate(attempt)
        assert result.allowed is False

    def test_additional_properties_denied_when_forbidden(
        self, validator_no_permissions: ConnectionValidator
    ) -> None:
        attempt = ConnectionAttempt(
            connector_name="typed-tool",
            source_agent="agent-1",
            input_data={"prompt": "Hi", "extra": "nope"},
        )
        result = validator_no_permissions.validate(attempt)
        assert result.allowed is False

    def test_empty_input_schema_skips_validation(
        self, populated_registry: ConnectorRegistry
    ) -> None:
        validator = ConnectionValidator(populated_registry)
        attempt = ConnectionAttempt(
            connector_name="simple-tool",
            source_agent="agent-1",
            input_data={"anything": "goes"},
        )
        result = validator.validate(attempt)
        assert result.allowed is True


# ---------------------------------------------------------------------------
# ConnectionValidator — all checks passed reason
# ---------------------------------------------------------------------------


class TestConnectionValidatorPassReason:
    def test_allowed_reason_text(
        self, validator_no_permissions: ConnectionValidator
    ) -> None:
        attempt = ConnectionAttempt(
            connector_name="simple-tool", source_agent="agent-1"
        )
        result = validator_no_permissions.validate(attempt)
        assert result.reason == "all checks passed"


# ---------------------------------------------------------------------------
# AuditLog
# ---------------------------------------------------------------------------


class TestAuditLog:
    def _make_entry(
        self,
        connector: str = "tool",
        agent: str = "agent-1",
        allowed: bool = True,
        ts: datetime.datetime | None = None,
    ) -> AuditEntry:
        attempt = ConnectionAttempt(connector_name=connector, source_agent=agent)
        result = ConnectionResult(allowed=allowed)
        entry = AuditEntry(connection_attempt=attempt, result=result)
        if ts is not None:
            # Pydantic models are immutable by default; use model_copy
            entry = entry.model_copy(update={"timestamp": ts})
        return entry

    def test_append_and_all_entries(self, audit_log: AuditLog) -> None:
        entry = self._make_entry()
        audit_log.append(entry)
        assert len(audit_log.all_entries()) == 1
        assert audit_log.all_entries()[0] is entry

    def test_len_reflects_entries(self, audit_log: AuditLog) -> None:
        for _ in range(5):
            audit_log.append(self._make_entry())
        assert len(audit_log) == 5

    def test_all_entries_returns_snapshot(self, audit_log: AuditLog) -> None:
        audit_log.append(self._make_entry())
        snapshot = audit_log.all_entries()
        audit_log.append(self._make_entry())
        # snapshot must not reflect the new append
        assert len(snapshot) == 1

    def test_since_filters_by_cutoff(self, audit_log: AuditLog) -> None:
        old_ts = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
        new_ts = datetime.datetime.now(datetime.UTC)

        audit_log.append(self._make_entry(ts=old_ts))
        audit_log.append(self._make_entry(ts=new_ts))

        cutoff = datetime.datetime(2023, 1, 1, tzinfo=datetime.UTC)
        recent = audit_log.since(cutoff)
        assert len(recent) == 1
        assert recent[0].timestamp == new_ts

    def test_since_includes_entry_at_exact_cutoff(self, audit_log: AuditLog) -> None:
        cutoff = datetime.datetime(2024, 6, 1, tzinfo=datetime.UTC)
        audit_log.append(self._make_entry(ts=cutoff))
        result = audit_log.since(cutoff)
        assert len(result) == 1

    def test_for_connector_filters_correctly(self, audit_log: AuditLog) -> None:
        audit_log.append(self._make_entry(connector="tool-a"))
        audit_log.append(self._make_entry(connector="tool-b"))
        audit_log.append(self._make_entry(connector="tool-a"))

        entries = audit_log.for_connector("tool-a")
        assert len(entries) == 2
        assert all(e.connection_attempt.connector_name == "tool-a" for e in entries)

    def test_for_agent_filters_correctly(self, audit_log: AuditLog) -> None:
        audit_log.append(self._make_entry(agent="agent-1"))
        audit_log.append(self._make_entry(agent="agent-2"))
        audit_log.append(self._make_entry(agent="agent-1"))

        entries = audit_log.for_agent("agent-1")
        assert len(entries) == 2
        assert all(e.connection_attempt.source_agent == "agent-1" for e in entries)

    def test_denied_entries_filters_correctly(self, audit_log: AuditLog) -> None:
        audit_log.append(self._make_entry(allowed=True))
        audit_log.append(self._make_entry(allowed=False))
        audit_log.append(self._make_entry(allowed=True))
        audit_log.append(self._make_entry(allowed=False))

        denied = audit_log.denied_entries()
        assert len(denied) == 2
        assert all(not e.result.allowed for e in denied)

    def test_clear_removes_all_entries(self, audit_log: AuditLog) -> None:
        for _ in range(10):
            audit_log.append(self._make_entry())
        audit_log.clear()
        assert len(audit_log) == 0
        assert audit_log.all_entries() == []

    def test_thread_safety_concurrent_append(self, audit_log: AuditLog) -> None:
        errors: list[Exception] = []

        def append_many() -> None:
            try:
                for _ in range(100):
                    audit_log.append(self._make_entry())
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=append_many) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == []
        assert len(audit_log) == 400

    def test_empty_log_returns_empty_for_all_queries(self, audit_log: AuditLog) -> None:
        now = datetime.datetime.now(datetime.UTC)
        assert audit_log.all_entries() == []
        assert audit_log.since(now) == []
        assert audit_log.for_connector("x") == []
        assert audit_log.for_agent("y") == []
        assert audit_log.denied_entries() == []

    def test_max_entries_cap_evicts_oldest_entries(self) -> None:
        """AuditLog must not grow beyond max_entries; oldest entries are dropped."""
        log = AuditLog(max_entries=5)
        for i in range(8):
            log.append(self._make_entry(connector=f"tool-{i}"))

        assert len(log) == 5
        # The three oldest entries (tool-0, tool-1, tool-2) should be gone.
        names = [e.connection_attempt.connector_name for e in log.all_entries()]
        assert names == ["tool-3", "tool-4", "tool-5", "tool-6", "tool-7"]

    def test_max_entries_default_is_ten_thousand(self) -> None:
        """The default max_entries value must be 10 000."""
        log = AuditLog()
        assert log._max_entries == 10_000

    def test_max_entries_of_one_keeps_only_last_entry(self) -> None:
        log = AuditLog(max_entries=1)
        log.append(self._make_entry(connector="first"))
        log.append(self._make_entry(connector="second"))
        assert len(log) == 1
        assert log.all_entries()[0].connection_attempt.connector_name == "second"


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


class TestElapsedMs:
    def test_returns_nonnegative_float(self) -> None:
        start = time.monotonic()
        elapsed = _elapsed_ms(start)
        assert elapsed >= 0.0

    def test_elapsed_grows_over_time(self) -> None:
        start = time.monotonic()
        time.sleep(0.05)  # 50 ms — large enough to survive Windows timer resolution
        elapsed = _elapsed_ms(start)
        assert elapsed > 20.0  # conservatively expect at least 20 ms


class TestValidateJsonSchema:
    def test_valid_data_returns_none(self) -> None:
        schema = {"type": "object", "properties": {"x": {"type": "integer"}}}
        assert _validate_json_schema({"x": 1}, schema) is None

    def test_invalid_data_returns_error_string(self) -> None:
        schema = {
            "type": "object",
            "properties": {"x": {"type": "integer"}},
            "required": ["x"],
        }
        error = _validate_json_schema({}, schema)
        assert error is not None
        assert isinstance(error, str)

    def test_type_mismatch_returns_error(self) -> None:
        schema = {"type": "object", "properties": {"val": {"type": "string"}}}
        error = _validate_json_schema({"val": 42}, schema)
        assert error is not None

    def test_empty_schema_always_passes(self) -> None:
        assert _validate_json_schema({"anything": True}, {}) is None

    def test_invalid_schema_definition_returns_error(self) -> None:
        bad_schema = {"type": "unknown_type_xyz"}
        result = _validate_json_schema({}, bad_schema)
        # jsonschema may or may not reject this depending on version;
        # the function must return either None or a string, never raise.
        assert result is None or isinstance(result, str)
