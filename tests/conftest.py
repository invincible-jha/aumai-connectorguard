"""Shared test fixtures for aumai-connectorguard tests."""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any

import pytest

from aumai_connectorguard.core import AuditLog, ConnectionValidator, ConnectorRegistry
from aumai_connectorguard.interceptor import RequestInterceptor
from aumai_connectorguard.models import (
    ConnectionAttempt,
    ConnectorSchema,
)
from aumai_connectorguard.rate_limiter import SlidingWindowRateLimiter

# ---------------------------------------------------------------------------
# Schema fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def simple_schema() -> ConnectorSchema:
    """A connector schema with no required permissions and no input schema."""
    return ConnectorSchema(name="simple-tool", version="1.0.0")


@pytest.fixture()
def schema_with_permissions() -> ConnectorSchema:
    """A connector schema that requires two permission tokens."""
    return ConnectorSchema(
        name="secure-tool",
        version="2.0.0",
        required_permissions=["read:data", "write:data"],
    )


@pytest.fixture()
def schema_with_input_schema() -> ConnectorSchema:
    """A connector schema that validates input data against a JSON Schema."""
    return ConnectorSchema(
        name="typed-tool",
        version="1.0.0",
        input_schema={
            "type": "object",
            "properties": {
                "prompt": {"type": "string"},
                "max_tokens": {"type": "integer"},
            },
            "required": ["prompt"],
            "additionalProperties": False,
        },
    )


@pytest.fixture()
def low_rate_schema() -> ConnectorSchema:
    """A connector schema with a tight rate limit of 3 req/min."""
    return ConnectorSchema(
        name="low-rate-tool",
        version="1.0.0",
        rate_limit=3,
    )


# ---------------------------------------------------------------------------
# Registry fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def empty_registry() -> ConnectorRegistry:
    """A brand-new registry with no registered connectors."""
    return ConnectorRegistry()


@pytest.fixture()
def populated_registry(
    simple_schema: ConnectorSchema,
    schema_with_permissions: ConnectorSchema,
    schema_with_input_schema: ConnectorSchema,
    low_rate_schema: ConnectorSchema,
) -> ConnectorRegistry:
    """Registry pre-loaded with four different connector schemas."""
    registry = ConnectorRegistry()
    registry.register(simple_schema)
    registry.register(schema_with_permissions)
    registry.register(schema_with_input_schema)
    registry.register(low_rate_schema)
    return registry


# ---------------------------------------------------------------------------
# Rate-limiter fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def fresh_rate_limiter() -> SlidingWindowRateLimiter:
    """A SlidingWindowRateLimiter with no recorded requests."""
    return SlidingWindowRateLimiter()


# ---------------------------------------------------------------------------
# Validator fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def validator_no_permissions(
    populated_registry: ConnectorRegistry,
) -> ConnectionValidator:
    """A validator that accepts any agent (no permissions configured)."""
    return ConnectionValidator(populated_registry)


@pytest.fixture()
def validator_with_agent(
    populated_registry: ConnectorRegistry,
    fresh_rate_limiter: SlidingWindowRateLimiter,
) -> ConnectionValidator:
    """A validator where 'trusted-agent' holds both secure-tool permissions."""
    return ConnectionValidator(
        registry=populated_registry,
        rate_limiter=fresh_rate_limiter,
        agent_permissions={"trusted-agent": ["read:data", "write:data"]},
    )


# ---------------------------------------------------------------------------
# Attempt fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def simple_attempt() -> ConnectionAttempt:
    """A minimal connection attempt targeting 'simple-tool'."""
    return ConnectionAttempt(
        connector_name="simple-tool",
        source_agent="agent-1",
    )


@pytest.fixture()
def typed_attempt() -> ConnectionAttempt:
    """An attempt carrying valid input data for 'typed-tool'."""
    return ConnectionAttempt(
        connector_name="typed-tool",
        source_agent="agent-1",
        input_data={"prompt": "Hello world", "max_tokens": 100},
    )


# ---------------------------------------------------------------------------
# AuditLog fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def audit_log() -> AuditLog:
    """An empty AuditLog."""
    return AuditLog()


# ---------------------------------------------------------------------------
# Interceptor fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def interceptor(
    validator_with_agent: ConnectionValidator,
    audit_log: AuditLog,
) -> RequestInterceptor:
    """A RequestInterceptor backed by validator_with_agent and a fresh audit log."""
    return RequestInterceptor(validator=validator_with_agent, audit_log=audit_log)


# ---------------------------------------------------------------------------
# File-system helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def schema_json_file(tmp_path: Path) -> Path:
    """Write a valid schema JSON file and return its path."""
    schema_data: dict[str, Any] = {
        "name": "openai-chat",
        "version": "1.0.0",
        "rate_limit": 60,
        "required_permissions": ["llm:call"],
        "input_schema": {"type": "object", "required": ["prompt"]},
        "output_schema": {"type": "object"},
    }
    file_path = tmp_path / "schema.json"
    file_path.write_text(json.dumps(schema_data), encoding="utf-8")
    return file_path


@pytest.fixture()
def registry_file(tmp_path: Path) -> Path:
    """Return path to a temporary registry JSON file (not yet created)."""
    return tmp_path / ".connectorguard_registry.json"


@pytest.fixture()
def agent_dir(tmp_path: Path) -> Path:
    """Return a temporary directory for agent connection log files."""
    directory = tmp_path / "agent_logs"
    directory.mkdir()
    return directory


@pytest.fixture()
def now_utc() -> datetime.datetime:
    """Current UTC datetime."""
    return datetime.datetime.now(datetime.UTC)
