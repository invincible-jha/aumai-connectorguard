"""Pydantic models for aumai-connectorguard."""

from __future__ import annotations

import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ConnectorSchema(BaseModel):
    """Declares the contract for a tool connector.

    ``input_schema`` and ``output_schema`` are JSON Schema objects (dicts)
    used to validate connection payloads at runtime.
    """

    name: str = Field(
        ..., description="Unique connector identifier, e.g. 'openai-chat'"
    )
    version: str = Field(..., description="SemVer string, e.g. '1.2.0'")
    input_schema: dict[str, Any] = Field(
        default_factory=dict,
        description="JSON Schema for the input payload",
    )
    output_schema: dict[str, Any] = Field(
        default_factory=dict,
        description="JSON Schema for the output payload",
    )
    rate_limit: int = Field(
        default=60,
        ge=1,
        description="Maximum requests per minute across all agents",
    )
    required_permissions: list[str] = Field(
        default_factory=list,
        description="Permission tokens an agent must hold to use this connector",
    )

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, value: str) -> str:
        """Reject blank connector names."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("connector name must not be blank")
        return stripped

    @field_validator("version")
    @classmethod
    def version_not_empty(cls, value: str) -> str:
        """Reject blank version strings."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("version must not be blank")
        return stripped


class ConnectionAttempt(BaseModel):
    """A single attempt by an agent to call a connector."""

    connector_name: str = Field(..., description="Name of the target connector")
    timestamp: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC)
    )
    input_data: dict[str, Any] = Field(default_factory=dict)
    source_agent: str = Field(
        default="unknown",
        description="Identifier of the agent making the call",
    )

    @field_validator("connector_name")
    @classmethod
    def connector_name_not_empty(cls, value: str) -> str:
        """Reject blank connector names."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("connector_name must not be blank")
        return stripped


class ConnectionResult(BaseModel):
    """Outcome of validating (and optionally executing) a connection attempt."""

    allowed: bool
    reason: str = Field(
        default="",
        description=(
            "Human-readable explanation of why the attempt was allowed or denied"
        ),
    )
    latency_ms: float = Field(
        default=0.0,
        ge=0.0,
        description="Time taken to validate the attempt in milliseconds",
    )


class AuditEntry(BaseModel):
    """Immutable audit record pairing an attempt with its result."""

    connection_attempt: ConnectionAttempt
    result: ConnectionResult
    timestamp: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC)
    )


class RateLimitState(BaseModel):
    """Mutable sliding-window state for one connector."""

    connector_name: str
    window_start: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC)
    )
    request_count: int = Field(default=0, ge=0)
    limit: int = Field(default=60, ge=1)

    def is_exhausted(self) -> bool:
        """Return True when the request count has reached the limit."""
        return self.request_count >= self.limit


__all__ = [
    "AuditEntry",
    "ConnectorSchema",
    "ConnectionAttempt",
    "ConnectionResult",
    "RateLimitState",
]
