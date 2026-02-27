# API Reference — aumai-connectorguard

All public symbols are importable directly from `aumai_connectorguard`:

```python
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
    check_rate_limit,
)
```

---

## Models (`aumai_connectorguard.models`)

### `ConnectorSchema`

```python
class ConnectorSchema(BaseModel):
    name:                 str            # required
    version:              str            # required
    input_schema:         dict[str, Any] # default {}
    output_schema:        dict[str, Any] # default {}
    rate_limit:           int            # default 60, ge=1
    required_permissions: list[str]      # default []
```

Declares the contract for a tool connector.

**Fields:**

| Field | Type | Default | Constraint | Description |
|---|---|---|---|---|
| `name` | `str` | required | not blank | Unique connector identifier, e.g. `"openai-chat"` |
| `version` | `str` | required | not blank | SemVer string, e.g. `"1.2.0"` |
| `input_schema` | `dict[str, Any]` | `{}` | — | JSON Schema for the input payload; empty = skip validation |
| `output_schema` | `dict[str, Any]` | `{}` | — | JSON Schema for the output payload (informational) |
| `rate_limit` | `int` | `60` | ge=1 | Maximum requests per minute |
| `required_permissions` | `list[str]` | `[]` | — | Permission tokens an agent must hold to use this connector |

**Validators:**
- `name`: stripped of whitespace; raises `ValueError` if blank after stripping.
- `version`: stripped of whitespace; raises `ValueError` if blank after stripping.

**Example:**

```python
from aumai_connectorguard import ConnectorSchema

schema = ConnectorSchema(
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
)
```

---

### `ConnectionAttempt`

```python
class ConnectionAttempt(BaseModel):
    connector_name: str            # required
    timestamp:      datetime       # default utcnow()
    input_data:     dict[str, Any] # default {}
    source_agent:   str            # default "unknown"
```

A single attempt by an agent to call a connector.

**Fields:**

| Field | Type | Default | Description |
|---|---|---|---|
| `connector_name` | `str` | required | Name of the target connector (must not be blank) |
| `timestamp` | `datetime` | `datetime.now(UTC)` | UTC timestamp of the attempt |
| `input_data` | `dict[str, Any]` | `{}` | Payload sent to the connector |
| `source_agent` | `str` | `"unknown"` | Identifier of the calling agent |

**Validators:**
- `connector_name`: stripped; raises `ValueError` if blank.

**Example:**

```python
from aumai_connectorguard import ConnectionAttempt

attempt = ConnectionAttempt(
    connector_name="openai-chat",
    source_agent="agent-1",
    input_data={"prompt": "Explain neural networks."},
)
print(attempt.timestamp)  # 2026-02-27T10:30:00+00:00
```

---

### `ConnectionResult`

```python
class ConnectionResult(BaseModel):
    allowed:    bool
    reason:     str   # default ""
    latency_ms: float # default 0.0, ge=0
```

Outcome of validating (and optionally executing) a connection attempt.

**Fields:**

| Field | Type | Description |
|---|---|---|
| `allowed` | `bool` | `True` when all validation checks passed |
| `reason` | `str` | Human-readable explanation. `"all checks passed"` on success |
| `latency_ms` | `float` | Time taken to validate the attempt in milliseconds |

**Example:**

```python
result: ConnectionResult = validator.validate(attempt)
if result.allowed:
    print(f"Allowed in {result.latency_ms:.2f}ms")
else:
    print(f"Denied: {result.reason}")
```

---

### `AuditEntry`

```python
class AuditEntry(BaseModel):
    connection_attempt: ConnectionAttempt
    result:             ConnectionResult
    timestamp:          datetime  # default utcnow()
```

Immutable audit record pairing an attempt with its result.

**Fields:**

| Field | Type | Description |
|---|---|---|
| `connection_attempt` | `ConnectionAttempt` | The original attempt |
| `result` | `ConnectionResult` | The validation outcome |
| `timestamp` | `datetime` | UTC timestamp when this entry was created |

**Example:**

```python
from aumai_connectorguard import AuditEntry, AuditLog

entry = AuditEntry(connection_attempt=attempt, result=result)
log = AuditLog()
log.append(entry)
```

---

### `RateLimitState`

```python
class RateLimitState(BaseModel):
    connector_name: str
    window_start:   datetime  # default utcnow()
    request_count:  int       # default 0, ge=0
    limit:          int       # default 60, ge=1

    def is_exhausted(self) -> bool: ...
```

Mutable sliding-window state for one connector. Used internally; exposed for inspection
and testing.

#### `RateLimitState.is_exhausted`

```python
def is_exhausted(self) -> bool
```

Return `True` when `request_count >= limit`.

---

## Core (`aumai_connectorguard.core`)

### `RegistryError`

```python
class RegistryError(Exception): ...
```

Raised when a connector lookup fails in `ConnectorRegistry.get()`.

---

### `ConnectorRegistry`

```python
class ConnectorRegistry:
    def __init__(self) -> None: ...
    def register(self, schema: ConnectorSchema) -> None: ...
    def get(self, name: str) -> ConnectorSchema: ...
    def all_names(self) -> list[str]: ...
    def unregister(self, name: str) -> None: ...
```

Register and look up `ConnectorSchema` objects. Thread-safe. Re-registering with the
same name overwrites the previous schema.

#### `ConnectorRegistry.register`

```python
def register(self, schema: ConnectorSchema) -> None
```

Add or replace a connector schema in the registry.

**Parameters:**
- `schema` (`ConnectorSchema`) — Schema to register.

#### `ConnectorRegistry.get`

```python
def get(self, name: str) -> ConnectorSchema
```

Return the schema for `name`.

**Parameters:**
- `name` (`str`) — Connector name to look up.

**Returns:** The registered `ConnectorSchema`.

**Raises:** `RegistryError` if no schema is registered under `name`.

#### `ConnectorRegistry.all_names`

```python
def all_names(self) -> list[str]
```

Return a sorted list of all registered connector names.

#### `ConnectorRegistry.unregister`

```python
def unregister(self, name: str) -> None
```

Remove a connector from the registry. No-op if not present.

**Example:**

```python
from aumai_connectorguard import ConnectorRegistry, ConnectorSchema

registry = ConnectorRegistry()
registry.register(ConnectorSchema(name="tool-a", version="1.0.0"))
registry.register(ConnectorSchema(name="tool-b", version="2.0.0"))

print(registry.all_names())       # ['tool-a', 'tool-b']
schema = registry.get("tool-a")
registry.unregister("tool-b")
print(registry.all_names())       # ['tool-a']
```

---

### `ConnectionValidator`

```python
class ConnectionValidator:
    def __init__(
        self,
        registry: ConnectorRegistry,
        rate_limiter: SlidingWindowRateLimiter | None = None,
        agent_permissions: dict[str, list[str]] | None = None,
        rate_limit_window_seconds: int = 60,
    ) -> None: ...

    def validate(self, attempt: ConnectionAttempt) -> ConnectionResult: ...
    def grant_permission(self, agent: str, permission: str) -> None: ...
    def revoke_permission(self, agent: str, permission: str) -> None: ...
```

Validate `ConnectionAttempt` objects through a 4-step pipeline. Thread-safe.

#### `ConnectionValidator.__init__`

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `registry` | `ConnectorRegistry` | required | Schema lookup source |
| `rate_limiter` | `SlidingWindowRateLimiter \| None` | `None` | Custom limiter; creates a fresh one if `None` |
| `agent_permissions` | `dict[str, list[str]] \| None` | `None` | Initial agent → permissions map |
| `rate_limit_window_seconds` | `int` | `60` | Sliding window size in seconds |

#### `ConnectionValidator.validate`

```python
def validate(self, attempt: ConnectionAttempt) -> ConnectionResult
```

Validate `attempt` through the 4-step pipeline.

**Pipeline steps (in order):**
1. Connector existence check via `ConnectorRegistry.get()`.
2. Agent permission check — all `required_permissions` must be held.
3. Rate limit check — sliding window via `SlidingWindowRateLimiter`.
4. JSON Schema input validation against `ConnectorSchema.input_schema`.

**Parameters:**
- `attempt` (`ConnectionAttempt`) — The attempt to validate.

**Returns:** `ConnectionResult` with `allowed` and `reason`.

**Notes:**
- Steps short-circuit: the first failure produces a `ConnectionResult(allowed=False)`
  immediately without evaluating later steps.
- Latency in milliseconds is always measured and set on the result.

**Example:**

```python
result = validator.validate(attempt)
print(result.allowed, result.reason, result.latency_ms)
```

#### `ConnectionValidator.grant_permission`

```python
def grant_permission(self, agent: str, permission: str) -> None
```

Add a permission token to an agent's allow-list. No-op if already granted.

#### `ConnectionValidator.revoke_permission`

```python
def revoke_permission(self, agent: str, permission: str) -> None
```

Remove a permission token from an agent's allow-list. No-op if not held.

**Example:**

```python
validator.grant_permission("agent-1", "llm:call")
validator.grant_permission("agent-1", "db:read")
validator.revoke_permission("agent-1", "db:read")
```

---

### `AuditLog`

```python
class AuditLog:
    def __init__(self, max_entries: int = 10_000) -> None: ...
    def append(self, entry: AuditEntry) -> None: ...
    def all_entries(self) -> list[AuditEntry]: ...
    def since(self, cutoff: datetime.datetime) -> list[AuditEntry]: ...
    def for_connector(self, connector_name: str) -> list[AuditEntry]: ...
    def for_agent(self, agent: str) -> list[AuditEntry]: ...
    def denied_entries(self) -> list[AuditEntry]: ...
    def clear(self) -> None: ...
    def __len__(self) -> int: ...
```

Append-only, thread-safe log of all connection attempts and results.

#### `AuditLog.__init__`

**Parameters:**
- `max_entries` (`int`) — Maximum entries before the oldest are evicted. Default `10_000`.

#### `AuditLog.append`

```python
def append(self, entry: AuditEntry) -> None
```

Add `entry` to the log. Evicts the oldest entries when at capacity.

#### `AuditLog.all_entries`

```python
def all_entries(self) -> list[AuditEntry]
```

Return a snapshot of all entries, oldest first.

#### `AuditLog.since`

```python
def since(self, cutoff: datetime.datetime) -> list[AuditEntry]
```

Return entries whose `timestamp` is >= `cutoff`.

**Parameters:**
- `cutoff` (`datetime.datetime`) — UTC-aware datetime lower bound.

**Example:**

```python
import datetime
cutoff = datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1)
recent = log.since(cutoff)
```

#### `AuditLog.for_connector`

```python
def for_connector(self, connector_name: str) -> list[AuditEntry]
```

Return all entries for a specific connector.

#### `AuditLog.for_agent`

```python
def for_agent(self, agent: str) -> list[AuditEntry]
```

Return all entries for a specific agent.

#### `AuditLog.denied_entries`

```python
def denied_entries(self) -> list[AuditEntry]
```

Return all entries where `result.allowed` is `False`.

#### `AuditLog.clear`

```python
def clear(self) -> None
```

Remove all entries. Useful in test teardown.

#### `AuditLog.__len__`

```python
def __len__(self) -> int
```

Return the current number of entries.

---

## Rate Limiter (`aumai_connectorguard.rate_limiter`)

### `SlidingWindowRateLimiter`

```python
class SlidingWindowRateLimiter:
    def __init__(self) -> None: ...
    def check_rate_limit(self, connector: str, window_seconds: int, max_requests: int) -> bool: ...
    def current_count(self, connector: str, window_seconds: int) -> int: ...
    def reset(self, connector: str) -> None: ...
```

Per-connector sliding-window rate limiter using a UTC timestamp deque. Thread-safe.

#### `SlidingWindowRateLimiter.check_rate_limit`

```python
def check_rate_limit(
    self,
    connector: str,
    window_seconds: int,
    max_requests: int,
) -> bool
```

Check whether a request to `connector` is within the rate limit. Records the timestamp
when allowed.

**Parameters:**
- `connector` (`str`) — Connector identifier (typically `"connector_name:agent_id"`).
- `window_seconds` (`int`) — Size of the sliding window in seconds.
- `max_requests` (`int`) — Maximum requests allowed within the window.

**Returns:** `True` if within limits and the request has been recorded. `False` if the
limit is already reached.

**Example:**

```python
from aumai_connectorguard import SlidingWindowRateLimiter

limiter = SlidingWindowRateLimiter()
for i in range(5):
    allowed = limiter.check_rate_limit("openai-chat:agent-1", 60, 3)
    print(i + 1, allowed)  # 1 True  2 True  3 True  4 False  5 False
```

#### `SlidingWindowRateLimiter.current_count`

```python
def current_count(self, connector: str, window_seconds: int) -> int
```

Return the number of requests recorded within the last `window_seconds`. Also evicts
stale timestamps as a side effect.

#### `SlidingWindowRateLimiter.reset`

```python
def reset(self, connector: str) -> None
```

Clear all recorded timestamps for `connector`. No-op if not present.

### `check_rate_limit` (module-level)

```python
def check_rate_limit(
    connector: str,
    window_seconds: int,
    max_requests: int,
    *,
    _limiter: SlidingWindowRateLimiter | None = None,
) -> bool
```

Module-level convenience using a shared global `SlidingWindowRateLimiter` instance.

**Parameters:**
- `connector` (`str`) — Connector identifier.
- `window_seconds` (`int`) — Window size in seconds.
- `max_requests` (`int`) — Maximum requests in the window.
- `_limiter` (`SlidingWindowRateLimiter | None`) — Optional override, useful in tests.

**Example:**

```python
from aumai_connectorguard import check_rate_limit

print(check_rate_limit("my-connector", 60, 10))  # True (first call on global limiter)
```

---

## Interceptor (`aumai_connectorguard.interceptor`)

### `InterceptorError`

```python
class InterceptorError(Exception): ...
```

Raised when a tool call is rejected by the `RequestInterceptor`.

---

### `RequestInterceptor`

```python
class RequestInterceptor:
    def __init__(
        self,
        validator: ConnectionValidator,
        audit_log: AuditLog | None = None,
    ) -> None: ...

    @property
    def audit_log(self) -> AuditLog: ...

    def wrap(
        self,
        connector_name: str,
        source_agent: str = "unknown",
    ) -> Callable[[F], F]: ...

    def intercept(
        self,
        connector_name: str,
        input_data: dict[str, Any],
        source_agent: str = "unknown",
    ) -> ConnectionResult: ...
```

Middleware that intercepts tool-call requests and validates them. Wraps any callable so
that every invocation is validated, logged, and rejected on failure.

#### `RequestInterceptor.__init__`

**Parameters:**
- `validator` (`ConnectionValidator`) — Validator to use for all calls.
- `audit_log` (`AuditLog | None`) — Audit log to write entries to; creates a new one if `None`.

#### `RequestInterceptor.audit_log`

Property returning the `AuditLog` associated with this interceptor.

#### `RequestInterceptor.wrap`

```python
def wrap(
    self,
    connector_name: str,
    source_agent: str = "unknown",
) -> Callable[[F], F]
```

Decorator factory that wraps a callable with pre-call validation and audit logging.

**Parameters:**
- `connector_name` (`str`) — The name of the connector this callable implements.
- `source_agent` (`str`) — The agent identifier making the call. Default `"unknown"`.

**Returns:** A decorator. When applied, the decorated callable validates on every
invocation and raises `InterceptorError` if validation fails.

**Notes:**
- `functools.wraps` is used to preserve the original callable's metadata.
- Positional args are stored as `arg_0`, `arg_1`, etc. in `input_data`.
- Both positional and keyword arguments are recorded in the audit entry.

**Example:**

```python
@interceptor.wrap(connector_name="openai-chat", source_agent="agent-1")
def call_openai(prompt: str, model: str = "gpt-4") -> str:
    # actual implementation
    return "response"

response = call_openai(prompt="hello")   # validates, executes, logs
```

#### `RequestInterceptor.intercept`

```python
def intercept(
    self,
    connector_name: str,
    input_data: dict[str, Any],
    source_agent: str = "unknown",
) -> ConnectionResult
```

Manually intercept a call without executing any underlying function. Useful when you
have already dispatched the call but want to record and validate the metadata.

**Parameters:**
- `connector_name` (`str`) — The target connector name.
- `input_data` (`dict[str, Any]`) — The payload sent to the connector.
- `source_agent` (`str`) — The calling agent identifier.

**Returns:** `ConnectionResult` with `allowed` and `reason` set.

**Example:**

```python
result = interceptor.intercept(
    connector_name="openai-chat",
    input_data={"prompt": "Summarize this."},
    source_agent="agent-2",
)
if not result.allowed:
    raise RuntimeError(f"Call denied: {result.reason}")
```
