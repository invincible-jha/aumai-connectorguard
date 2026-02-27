"""Tests for aumai_connectorguard.models."""

from __future__ import annotations

import datetime

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from aumai_connectorguard.models import (
    AuditEntry,
    ConnectionAttempt,
    ConnectionResult,
    ConnectorSchema,
    RateLimitState,
)

# ---------------------------------------------------------------------------
# ConnectorSchema
# ---------------------------------------------------------------------------


class TestConnectorSchema:
    def test_minimal_schema_succeeds(self) -> None:
        schema = ConnectorSchema(name="my-tool", version="1.0.0")
        assert schema.name == "my-tool"
        assert schema.version == "1.0.0"
        assert schema.rate_limit == 60
        assert schema.input_schema == {}
        assert schema.output_schema == {}
        assert schema.required_permissions == []

    def test_full_schema_round_trip(self) -> None:
        schema = ConnectorSchema(
            name="openai-chat",
            version="2.3.1",
            input_schema={"type": "object"},
            output_schema={"type": "object"},
            rate_limit=120,
            required_permissions=["llm:call", "data:read"],
        )
        dumped = schema.model_dump()
        reloaded = ConnectorSchema.model_validate(dumped)
        assert reloaded == schema

    def test_name_stripped_of_whitespace(self) -> None:
        schema = ConnectorSchema(name="  my-tool  ", version="1.0.0")
        assert schema.name == "my-tool"

    def test_version_stripped_of_whitespace(self) -> None:
        schema = ConnectorSchema(name="my-tool", version="  2.0.0  ")
        assert schema.version == "2.0.0"

    def test_blank_name_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError, match="connector name must not be blank"):
            ConnectorSchema(name="   ", version="1.0.0")

    def test_empty_name_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError, match="connector name must not be blank"):
            ConnectorSchema(name="", version="1.0.0")

    def test_blank_version_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError, match="version must not be blank"):
            ConnectorSchema(name="my-tool", version="   ")

    def test_rate_limit_must_be_at_least_one(self) -> None:
        with pytest.raises(ValidationError):
            ConnectorSchema(name="my-tool", version="1.0.0", rate_limit=0)

    def test_rate_limit_negative_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            ConnectorSchema(name="my-tool", version="1.0.0", rate_limit=-5)

    def test_rate_limit_minimum_boundary(self) -> None:
        schema = ConnectorSchema(name="my-tool", version="1.0.0", rate_limit=1)
        assert schema.rate_limit == 1

    def test_required_permissions_default_empty_list(self) -> None:
        schema = ConnectorSchema(name="my-tool", version="1.0.0")
        assert schema.required_permissions == []

    def test_required_permissions_populated(self) -> None:
        schema = ConnectorSchema(
            name="my-tool",
            version="1.0.0",
            required_permissions=["perm:a", "perm:b"],
        )
        assert "perm:a" in schema.required_permissions
        assert "perm:b" in schema.required_permissions

    @given(
        name=st.text(min_size=1).map(str.strip).filter(lambda s: len(s) > 0),
        version=st.text(min_size=1).map(str.strip).filter(lambda s: len(s) > 0),
        rate_limit=st.integers(min_value=1, max_value=10_000),
    )
    @settings(max_examples=50)
    def test_property_valid_schemas_always_construct(
        self, name: str, version: str, rate_limit: int
    ) -> None:
        schema = ConnectorSchema(name=name, version=version, rate_limit=rate_limit)
        assert schema.name == name
        assert schema.version == version
        assert schema.rate_limit == rate_limit


# ---------------------------------------------------------------------------
# ConnectionAttempt
# ---------------------------------------------------------------------------


class TestConnectionAttempt:
    def test_minimal_attempt_defaults(self) -> None:
        attempt = ConnectionAttempt(connector_name="my-tool")
        assert attempt.connector_name == "my-tool"
        assert attempt.source_agent == "unknown"
        assert attempt.input_data == {}
        assert attempt.timestamp.tzinfo is not None

    def test_timestamp_is_utc_aware(self) -> None:
        attempt = ConnectionAttempt(connector_name="my-tool")
        assert attempt.timestamp.tzinfo == datetime.UTC

    def test_custom_source_agent(self) -> None:
        attempt = ConnectionAttempt(connector_name="my-tool", source_agent="agent-42")
        assert attempt.source_agent == "agent-42"

    def test_input_data_populated(self) -> None:
        attempt = ConnectionAttempt(
            connector_name="my-tool",
            input_data={"key": "value", "num": 99},
        )
        assert attempt.input_data == {"key": "value", "num": 99}

    def test_blank_connector_name_raises(self) -> None:
        with pytest.raises(ValidationError, match="connector_name must not be blank"):
            ConnectionAttempt(connector_name="  ")

    def test_empty_connector_name_raises(self) -> None:
        with pytest.raises(ValidationError, match="connector_name must not be blank"):
            ConnectionAttempt(connector_name="")

    def test_connector_name_stripped(self) -> None:
        attempt = ConnectionAttempt(connector_name="  my-tool  ")
        assert attempt.connector_name == "my-tool"

    def test_custom_timestamp_preserved(self) -> None:
        ts = datetime.datetime(2025, 1, 1, 12, 0, 0, tzinfo=datetime.UTC)
        attempt = ConnectionAttempt(connector_name="my-tool", timestamp=ts)
        assert attempt.timestamp == ts


# ---------------------------------------------------------------------------
# ConnectionResult
# ---------------------------------------------------------------------------


class TestConnectionResult:
    def test_allowed_result(self) -> None:
        result = ConnectionResult(allowed=True, reason="all checks passed")
        assert result.allowed is True
        assert result.reason == "all checks passed"
        assert result.latency_ms == 0.0

    def test_denied_result(self) -> None:
        result = ConnectionResult(allowed=False, reason="rate limit exceeded")
        assert result.allowed is False

    def test_latency_stored(self) -> None:
        result = ConnectionResult(allowed=True, latency_ms=12.345)
        assert result.latency_ms == pytest.approx(12.345)

    def test_latency_cannot_be_negative(self) -> None:
        with pytest.raises(ValidationError):
            ConnectionResult(allowed=True, latency_ms=-1.0)

    def test_reason_defaults_empty_string(self) -> None:
        result = ConnectionResult(allowed=True)
        assert result.reason == ""

    def test_latency_zero_boundary(self) -> None:
        result = ConnectionResult(allowed=False, latency_ms=0.0)
        assert result.latency_ms == 0.0


# ---------------------------------------------------------------------------
# AuditEntry
# ---------------------------------------------------------------------------


class TestAuditEntry:
    def test_audit_entry_links_attempt_and_result(self) -> None:
        attempt = ConnectionAttempt(connector_name="my-tool", source_agent="agent-1")
        result = ConnectionResult(allowed=True, reason="ok")
        entry = AuditEntry(connection_attempt=attempt, result=result)
        assert entry.connection_attempt is attempt
        assert entry.result is result

    def test_audit_entry_timestamp_utc(self) -> None:
        attempt = ConnectionAttempt(connector_name="my-tool")
        result = ConnectionResult(allowed=False)
        entry = AuditEntry(connection_attempt=attempt, result=result)
        assert entry.timestamp.tzinfo is not None

    def test_audit_entry_round_trip(self) -> None:
        attempt = ConnectionAttempt(connector_name="my-tool", source_agent="a1")
        result = ConnectionResult(allowed=True, reason="ok", latency_ms=5.0)
        entry = AuditEntry(connection_attempt=attempt, result=result)
        dumped = entry.model_dump(mode="json")
        reloaded = AuditEntry.model_validate(dumped)
        assert reloaded.connection_attempt.connector_name == "my-tool"
        assert reloaded.result.allowed is True


# ---------------------------------------------------------------------------
# RateLimitState
# ---------------------------------------------------------------------------


class TestRateLimitState:
    def test_default_state_not_exhausted(self) -> None:
        state = RateLimitState(connector_name="my-tool")
        assert state.request_count == 0
        assert state.limit == 60
        assert state.is_exhausted() is False

    def test_exhausted_when_count_equals_limit(self) -> None:
        state = RateLimitState(connector_name="my-tool", request_count=60, limit=60)
        assert state.is_exhausted() is True

    def test_exhausted_when_count_exceeds_limit(self) -> None:
        state = RateLimitState(connector_name="my-tool", request_count=61, limit=60)
        assert state.is_exhausted() is True

    def test_not_exhausted_one_below_limit(self) -> None:
        state = RateLimitState(connector_name="my-tool", request_count=59, limit=60)
        assert state.is_exhausted() is False

    def test_request_count_cannot_be_negative(self) -> None:
        with pytest.raises(ValidationError):
            RateLimitState(connector_name="my-tool", request_count=-1)

    def test_limit_cannot_be_zero(self) -> None:
        with pytest.raises(ValidationError):
            RateLimitState(connector_name="my-tool", limit=0)

    def test_custom_limit(self) -> None:
        state = RateLimitState(connector_name="my-tool", limit=10, request_count=10)
        assert state.is_exhausted() is True

    def test_window_start_is_utc(self) -> None:
        state = RateLimitState(connector_name="my-tool")
        assert state.window_start.tzinfo is not None

    @given(
        count=st.integers(min_value=0, max_value=1000),
        limit=st.integers(min_value=1, max_value=1000),
    )
    @settings(max_examples=100)
    def test_property_is_exhausted_matches_comparison(
        self, count: int, limit: int
    ) -> None:
        state = RateLimitState(connector_name="x", request_count=count, limit=limit)
        assert state.is_exhausted() == (count >= limit)
