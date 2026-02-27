"""aumai-connectorguard quickstart example.

Demonstrates:
- Registering connector schemas and building a ConnectorRegistry.
- Validating ConnectionAttempt objects through the 4-step pipeline.
- Dynamic permission granting and revocation.
- Using RequestInterceptor to wrap tool functions as decorators.
- Querying the AuditLog.
- Rate limiting with SlidingWindowRateLimiter.

Run this file directly::

    python examples/quickstart.py
"""

from __future__ import annotations

import datetime

from aumai_connectorguard import (
    AuditEntry,
    AuditLog,
    ConnectorRegistry,
    ConnectorSchema,
    ConnectionAttempt,
    ConnectionResult,
    ConnectionValidator,
    InterceptorError,
    RequestInterceptor,
    SlidingWindowRateLimiter,
)


# ---------------------------------------------------------------------------
# Demo 1: Basic connector registration and validation
# ---------------------------------------------------------------------------


def demo_basic_validation() -> None:
    """Register a connector schema and validate connection attempts.

    Shows the 4-step pipeline: connector lookup, permission check,
    rate limit check, and JSON Schema input validation.
    """
    print("=" * 60)
    print("Demo 1: Basic connector registration and validation")
    print("=" * 60)

    # --- Set up registry ---
    registry = ConnectorRegistry()
    registry.register(ConnectorSchema(
        name="openai-chat",
        version="1.0.0",
        rate_limit=30,
        required_permissions=["llm:call"],
        input_schema={
            "type": "object",
            "properties": {
                "prompt":     {"type": "string"},
                "max_tokens": {"type": "integer", "minimum": 1},
            },
            "required": ["prompt"],
        },
    ))
    print(f"  Registered connectors: {registry.all_names()}")

    # --- Set up validator with initial permissions ---
    validator = ConnectionValidator(
        registry,
        agent_permissions={
            "agent-with-access": ["llm:call"],
            "agent-no-access":   [],
        },
    )

    # Attempt 1: valid call — all checks should pass
    attempt_ok = ConnectionAttempt(
        connector_name="openai-chat",
        source_agent="agent-with-access",
        input_data={"prompt": "Explain the transformer architecture."},
    )
    result_ok = validator.validate(attempt_ok)
    print(f"  [{'ALLOW' if result_ok.allowed else 'DENY '}] {attempt_ok.source_agent}"
          f" -> openai-chat: {result_ok.reason} ({result_ok.latency_ms:.2f}ms)")

    # Attempt 2: missing permission
    attempt_no_perm = ConnectionAttempt(
        connector_name="openai-chat",
        source_agent="agent-no-access",
        input_data={"prompt": "hello"},
    )
    result_no_perm = validator.validate(attempt_no_perm)
    print(f"  [{'ALLOW' if result_no_perm.allowed else 'DENY '}] {attempt_no_perm.source_agent}"
          f" -> openai-chat: {result_no_perm.reason}")

    # Attempt 3: connector not registered
    attempt_missing = ConnectionAttempt(
        connector_name="nonexistent-tool",
        source_agent="agent-with-access",
        input_data={},
    )
    result_missing = validator.validate(attempt_missing)
    print(f"  [{'ALLOW' if result_missing.allowed else 'DENY '}] {attempt_missing.source_agent}"
          f" -> nonexistent-tool: {result_missing.reason}")

    # Attempt 4: invalid input (missing required field "prompt")
    attempt_bad_input = ConnectionAttempt(
        connector_name="openai-chat",
        source_agent="agent-with-access",
        input_data={"max_tokens": 100},   # "prompt" is missing
    )
    result_bad = validator.validate(attempt_bad_input)
    print(f"  [{'ALLOW' if result_bad.allowed else 'DENY '}] bad input: {result_bad.reason}")
    print()


# ---------------------------------------------------------------------------
# Demo 2: Dynamic permission management
# ---------------------------------------------------------------------------


def demo_dynamic_permissions() -> None:
    """Grant and revoke permissions at runtime.

    ConnectionValidator.grant_permission() and revoke_permission() take
    effect immediately for subsequent validate() calls.
    """
    print("=" * 60)
    print("Demo 2: Dynamic permission management")
    print("=" * 60)

    registry = ConnectorRegistry()
    registry.register(ConnectorSchema(
        name="db-query",
        version="1.0.0",
        required_permissions=["db:read"],
        input_schema={
            "type": "object",
            "properties": {"sql": {"type": "string"}},
            "required": ["sql"],
        },
    ))

    validator = ConnectionValidator(registry)   # agent-1 starts with no permissions

    def try_connect(label: str) -> None:
        attempt = ConnectionAttempt(
            connector_name="db-query",
            source_agent="agent-1",
            input_data={"sql": "SELECT 1"},
        )
        result = validator.validate(attempt)
        status = "ALLOW" if result.allowed else "DENY "
        print(f"  [{status}] {label}: {result.reason}")

    try_connect("before grant")          # denied — missing db:read

    validator.grant_permission("agent-1", "db:read")
    try_connect("after grant")           # allowed

    validator.revoke_permission("agent-1", "db:read")
    try_connect("after revoke")          # denied again
    print()


# ---------------------------------------------------------------------------
# Demo 3: RequestInterceptor decorator
# ---------------------------------------------------------------------------


def demo_interceptor_decorator() -> None:
    """Wrap tool functions with the RequestInterceptor decorator.

    The @interceptor.wrap() decorator validates every call transparently.
    Allowed calls execute normally; denied calls raise InterceptorError.
    """
    print("=" * 60)
    print("Demo 3: RequestInterceptor decorator")
    print("=" * 60)

    registry = ConnectorRegistry()
    registry.register(ConnectorSchema(
        name="calculator",
        version="1.0.0",
        required_permissions=["math:use"],
        input_schema={
            "type": "object",
            "properties": {
                "x": {"type": "number"},
                "y": {"type": "number"},
            },
            "required": ["x", "y"],
        },
    ))

    audit_log = AuditLog()
    validator = ConnectionValidator(
        registry,
        agent_permissions={"trusted-agent": ["math:use"]},
    )
    interceptor = RequestInterceptor(validator, audit_log)

    # --- Wrap a tool function ---
    @interceptor.wrap(connector_name="calculator", source_agent="trusted-agent")
    def add(x: float, y: float) -> float:
        """Add two numbers."""
        return x + y

    # Allowed call
    result = add(x=10.5, y=4.5)
    print(f"  add(10.5, 4.5) = {result}")

    # A second wrapper for an untrusted agent
    @interceptor.wrap(connector_name="calculator", source_agent="untrusted-agent")
    def add_as_bad(x: float, y: float) -> float:
        return x + y

    try:
        add_as_bad(x=1.0, y=2.0)
    except InterceptorError as exc:
        print(f"  InterceptorError raised: {exc}")

    # Manual intercept (for post-dispatch recording)
    manual_result: ConnectionResult = interceptor.intercept(
        connector_name="calculator",
        input_data={"x": 7, "y": 3},
        source_agent="trusted-agent",
    )
    print(f"  manual intercept: allowed={manual_result.allowed}, reason={manual_result.reason!r}")

    # Inspect audit log
    print(f"  Audit log has {len(audit_log)} entries:")
    for entry in audit_log.all_entries():
        status = "ALLOW" if entry.result.allowed else "DENY "
        print(f"    [{status}] agent={entry.connection_attempt.source_agent}"
              f" -> {entry.connection_attempt.connector_name}"
              f" : {entry.result.reason}")
    print()


# ---------------------------------------------------------------------------
# Demo 4: AuditLog querying
# ---------------------------------------------------------------------------


def demo_audit_log() -> None:
    """Show AuditLog filtering: by agent, connector, time window, and denied status."""
    print("=" * 60)
    print("Demo 4: AuditLog querying")
    print("=" * 60)

    log = AuditLog(max_entries=100)

    # Manually build some audit entries
    registry = ConnectorRegistry()
    registry.register(ConnectorSchema(name="tool-a", version="1.0.0"))
    registry.register(ConnectorSchema(name="tool-b", version="1.0.0",
                                       required_permissions=["b:use"]))

    validator = ConnectionValidator(registry, agent_permissions={"agent-x": ["b:use"]})

    attempts = [
        ConnectionAttempt(connector_name="tool-a", source_agent="agent-x"),
        ConnectionAttempt(connector_name="tool-b", source_agent="agent-x"),
        ConnectionAttempt(connector_name="tool-a", source_agent="agent-y"),
        ConnectionAttempt(connector_name="tool-b", source_agent="agent-y"),   # will be denied
        ConnectionAttempt(connector_name="nonexistent", source_agent="agent-x"),  # will be denied
    ]
    for att in attempts:
        result = validator.validate(att)
        log.append(AuditEntry(connection_attempt=att, result=result))

    print(f"  Total entries   : {len(log)}")
    print(f"  Denied entries  : {len(log.denied_entries())}")
    print(f"  For agent-x     : {len(log.for_agent('agent-x'))} entries")
    print(f"  For tool-a      : {len(log.for_connector('tool-a'))} entries")

    cutoff = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=5)
    print(f"  Since 5s ago    : {len(log.since(cutoff))} entries (should be all {len(log)})")
    print()


# ---------------------------------------------------------------------------
# Demo 5: Rate limiting
# ---------------------------------------------------------------------------


def demo_rate_limiting() -> None:
    """Demonstrate the sliding-window rate limiter.

    The key is connector_name:agent_id — each agent has its own counter per
    connector within the shared SlidingWindowRateLimiter.
    """
    print("=" * 60)
    print("Demo 5: SlidingWindowRateLimiter")
    print("=" * 60)

    limiter = SlidingWindowRateLimiter()
    window_seconds = 60
    max_requests = 3
    key = "openai-chat:agent-1"

    print(f"  Window: {window_seconds}s, Max: {max_requests} requests")
    for i in range(1, 6):
        allowed = limiter.check_rate_limit(key, window_seconds, max_requests)
        count = limiter.current_count(key, window_seconds)
        print(f"  Call {i}: {'ALLOW' if allowed else 'DENY '}"
              f"  (current count in window: {count}/{max_requests})")

    # Reset for a different key — does not affect other keys
    limiter.reset(key)
    allowed_after_reset = limiter.check_rate_limit(key, window_seconds, max_requests)
    print(f"  After reset, call 1: {'ALLOW' if allowed_after_reset else 'DENY '}")
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run all quickstart demos in sequence."""
    demo_basic_validation()
    demo_dynamic_permissions()
    demo_interceptor_decorator()
    demo_audit_log()
    demo_rate_limiting()
    print("All quickstart demos complete.")


if __name__ == "__main__":
    main()
