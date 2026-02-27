# Getting Started with aumai-connectorguard

This guide walks you from zero to a working connector validation pipeline in under five
minutes, then covers the patterns you will encounter most in production.

---

## Prerequisites

- Python 3.11 or newer
- `pip` (comes with Python)
- A terminal / command prompt

---

## Installation

### From PyPI (recommended)

```bash
pip install aumai-connectorguard
```

### From source

```bash
git clone https://github.com/aumai/aumai-connectorguard.git
cd aumai-connectorguard
pip install -e .
```

### Development mode (with test dependencies)

```bash
git clone https://github.com/aumai/aumai-connectorguard.git
cd aumai-connectorguard
pip install -e ".[dev]"
```

Verify your installation:

```bash
aumai-connectorguard --version
python -c "import aumai_connectorguard; print(aumai_connectorguard.__version__)"
```

---

## Your First Connector Guard

This tutorial builds a full validation pipeline: define a connector schema, register it,
set up a validator with agent permissions, and validate a call.

### Step 1 — Define a connector schema

A connector schema declares the contract for a tool: what it accepts (JSON Schema), who
can call it (permissions), and how often (rate limit). Create `openai-chat.json`:

```json
{
  "name": "openai-chat",
  "version": "1.0.0",
  "rate_limit": 30,
  "required_permissions": ["llm:call"],
  "input_schema": {
    "type": "object",
    "properties": {
      "prompt": {"type": "string"},
      "model":  {"type": "string"},
      "max_tokens": {"type": "integer", "minimum": 1}
    },
    "required": ["prompt"],
    "additionalProperties": false
  },
  "output_schema": {
    "type": "object",
    "properties": {
      "content": {"type": "string"}
    }
  }
}
```

### Step 2 — Register it via CLI

```bash
aumai-connectorguard register --schema openai-chat.json
# Registered connector 'openai-chat' v1.0.0 -> .connectorguard_registry.json
```

This writes the schema to `.connectorguard_registry.json` in the current directory.

### Step 3 — Set up a validator in Python

```python
from aumai_connectorguard import (
    ConnectorRegistry,
    ConnectorSchema,
    ConnectionAttempt,
    ConnectionValidator,
)

# Build the registry programmatically
registry = ConnectorRegistry()
registry.register(ConnectorSchema(
    name="openai-chat",
    version="1.0.0",
    rate_limit=30,
    required_permissions=["llm:call"],
    input_schema={
        "type": "object",
        "properties": {"prompt": {"type": "string"}},
        "required": ["prompt"],
    },
))

# Create a validator with agent permissions
validator = ConnectionValidator(
    registry,
    agent_permissions={
        "agent-1": ["llm:call"],         # full access
        "agent-readonly": [],            # no llm:call — will be denied
    },
)
```

### Step 4 — Validate a call

```python
attempt = ConnectionAttempt(
    connector_name="openai-chat",
    source_agent="agent-1",
    input_data={"prompt": "Explain quantum entanglement in plain English."},
)
result = validator.validate(attempt)
print(result.allowed)    # True
print(result.reason)     # all checks passed
print(result.latency_ms) # 0.12
```

Try a call that should be denied:

```python
bad_attempt = ConnectionAttempt(
    connector_name="openai-chat",
    source_agent="agent-readonly",
    input_data={"prompt": "hello"},
)
denied = validator.validate(bad_attempt)
print(denied.allowed)  # False
print(denied.reason)   # agent 'agent-readonly' is missing required permissions: llm:call
```

### Step 5 — Add audit logging

```python
from aumai_connectorguard import AuditLog, AuditEntry

audit_log = AuditLog()
audit_log.append(AuditEntry(connection_attempt=attempt, result=result))
audit_log.append(AuditEntry(connection_attempt=bad_attempt, result=denied))

print(len(audit_log))                  # 2
print(len(audit_log.denied_entries())) # 1
```

---

## Common Patterns

### Pattern 1 — Decorator-based interception

Use `RequestInterceptor.wrap()` to automatically validate and log every call to a tool
function without changing any call-site code.

```python
from aumai_connectorguard import (
    AuditLog,
    ConnectorRegistry,
    ConnectorSchema,
    ConnectionValidator,
    RequestInterceptor,
)

registry = ConnectorRegistry()
registry.register(ConnectorSchema(
    name="calculator",
    version="1.0.0",
    required_permissions=["math:use"],
    input_schema={
        "type": "object",
        "properties": {"x": {"type": "number"}, "y": {"type": "number"}},
        "required": ["x", "y"],
    },
))

validator = ConnectionValidator(registry, agent_permissions={"agent-1": ["math:use"]})
audit_log = AuditLog()
interceptor = RequestInterceptor(validator, audit_log)

@interceptor.wrap(connector_name="calculator", source_agent="agent-1")
def add(x: float, y: float) -> float:
    """Add two numbers."""
    return x + y

print(add(x=10.5, y=4.5))   # 15.0 — validated, executed, logged
print(len(audit_log))        # 1
```

If the agent lacks permission, the call raises `InterceptorError`:

```python
from aumai_connectorguard import InterceptorError

@interceptor.wrap(connector_name="calculator", source_agent="agent-noperm")
def add_as_bad_agent(x: float, y: float) -> float:
    return x + y

try:
    add_as_bad_agent(x=1.0, y=2.0)
except InterceptorError as exc:
    print(exc)
    # connection to 'calculator' denied: agent 'agent-noperm' is missing ...
```

### Pattern 2 — Dynamic permission management

Grant and revoke permissions at runtime without rebuilding the validator.

```python
validator = ConnectionValidator(registry)

# Grant access
validator.grant_permission("agent-1", "llm:call")
validator.grant_permission("agent-1", "db:read")

# Later, revoke when the task is complete
validator.revoke_permission("agent-1", "db:read")

# Grant a different agent
validator.grant_permission("agent-2", "llm:call")
```

### Pattern 3 — Schema-driven input validation

Register a connector with a strict JSON Schema to catch malformed inputs before they
reach your tool.

```python
from aumai_connectorguard import ConnectorRegistry, ConnectorSchema, ConnectionAttempt, ConnectionValidator

registry = ConnectorRegistry()
registry.register(ConnectorSchema(
    name="db-query",
    version="1.0.0",
    required_permissions=["db:read"],
    input_schema={
        "type": "object",
        "properties": {
            "sql":    {"type": "string", "minLength": 1},
            "params": {"type": "array", "items": {"type": ["string", "number", "null"]}},
        },
        "required": ["sql"],
        "additionalProperties": False,
    },
))

validator = ConnectionValidator(registry, agent_permissions={"agent-1": ["db:read"]})

# Valid
ok = validator.validate(ConnectionAttempt(
    connector_name="db-query",
    source_agent="agent-1",
    input_data={"sql": "SELECT * FROM users WHERE id = ?", "params": [42]},
))
print(ok.allowed, ok.reason)  # True  all checks passed

# Invalid — unexpected field
bad = validator.validate(ConnectionAttempt(
    connector_name="db-query",
    source_agent="agent-1",
    input_data={"sql": "SELECT 1", "evil_key": "drop table users"},
))
print(bad.allowed, bad.reason)
# False  input validation failed: Additional properties are not allowed ('evil_key' ...)
```

### Pattern 4 — Rate limit monitoring

Check how many requests remain in the current window before deciding whether to dispatch.

```python
from aumai_connectorguard import SlidingWindowRateLimiter

limiter = SlidingWindowRateLimiter()
WINDOW = 60
MAX_REQUESTS = 5

for i in range(7):
    allowed = limiter.check_rate_limit("openai-chat:agent-1", WINDOW, MAX_REQUESTS)
    count = limiter.current_count("openai-chat:agent-1", WINDOW)
    print(f"  call {i+1}: {'OK  ' if allowed else 'DENY'}  count={count}/{MAX_REQUESTS}")
```

### Pattern 5 — Watch mode for offline log analysis

Point `watch` at an agent's log output directory to validate all recorded connection
attempts without running the agent live.

```bash
# agent produces *.json log files as it runs
aumai-connectorguard watch --agent /var/log/agent_run --agent-id prod-agent-1
```

Log files can contain a single JSON object or an array:

```json
[
  {"connector_name": "openai-chat", "input_data": {"prompt": "hello"}, "source_agent": "prod-agent-1"},
  {"connector_name": "db-write", "input_data": {"table": "users", "row": {}}}
]
```

---

## Troubleshooting FAQ

**Q: `RegistryError: connector 'X' is not registered`**

The connector name in the `ConnectionAttempt` does not match any registered schema.
Check spelling (names are case-sensitive) and verify the schema was registered before
validation was called.

```python
print(registry.all_names())  # ['calculator', 'db-query', 'openai-chat']
```

---

**Q: Validation always fails with a missing permission even though I granted it.**

`grant_permission()` modifies the validator's internal `_agent_permissions` dict under a
lock. If you are using a separate `ConnectionValidator` instance from the one that
intercepted the call, the grant does not apply. Use the same validator instance throughout.

Also note the `agent_permissions` constructor parameter uses the initial state; grants
after construction are live but independent of the constructor dict.

---

**Q: My `@interceptor.wrap` decorated function still lets through calls it should block.**

Check that the `connector_name` passed to `@interceptor.wrap` exactly matches the name
registered in the `ConnectorRegistry`. If the connector is not registered, step 1 of
the pipeline returns `allowed=False` with a `RegistryError` message — but the decorator
raises `InterceptorError`, so the call is blocked. Double-check with:

```python
print(registry.all_names())
```

---

**Q: `AuditEntry.model_validate` raises an error when loading old log files.**

Older log entries may be missing the `timestamp` field (added in a later version). The
`audit` CLI command silently skips malformed entries with `pass` to avoid aborting on
partially corrupted log files. In Python code, wrap the call in a try/except block:

```python
from pydantic import ValidationError
for raw in raw_entries:
    try:
        audit_log.append(AuditEntry.model_validate(raw))
    except ValidationError:
        pass  # skip malformed entries
```

---

**Q: Rate limiting is not resetting between test runs.**

`SlidingWindowRateLimiter` is stateful. In tests, either create a fresh instance per test
or call `limiter.reset("connector:agent")` in your teardown. The module-level
`check_rate_limit()` function uses a shared global limiter (`_global_limiter`) which
persists across calls in the same process.

```python
from aumai_connectorguard.rate_limiter import _global_limiter
_global_limiter.reset("my-connector:my-agent")
```

Or pass a fresh limiter directly:

```python
from aumai_connectorguard import SlidingWindowRateLimiter, check_rate_limit
fresh = SlidingWindowRateLimiter()
result = check_rate_limit("conn", 60, 10, _limiter=fresh)
```

---

**Q: Can I use `aumai-connectorguard` without the CLI?**

Yes, the CLI is entirely optional. Every feature is available via the Python API. The CLI
is a convenience wrapper for shell scripts, CI pipelines, and quick debugging.

---

## Next Steps

- Read the [API Reference](api-reference.md) for full class and method documentation.
- Explore the [examples/](../examples/) directory for runnable demo scripts.
- See the main [README](../README.md) for architecture diagrams and integration guides.
