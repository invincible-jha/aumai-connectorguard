"""CLI entry point for aumai-connectorguard."""

from __future__ import annotations

import datetime
import json
import re
import sys
from pathlib import Path
from typing import Any

import click

from aumai_connectorguard.core import (
    AuditLog,
    ConnectionValidator,
    ConnectorRegistry,
)
from aumai_connectorguard.models import AuditEntry, ConnectionAttempt, ConnectorSchema


@click.group()
@click.version_option(package_name="aumai-connectorguard")
def main() -> None:
    """AumAI ConnectorGuard — runtime validation for agent-to-tool connections.

    Use 'aumai-connectorguard --help' to see available sub-commands.
    """


# ---------------------------------------------------------------------------
# register
# ---------------------------------------------------------------------------


@main.command("register")
@click.option(
    "--schema",
    "schema_path",
    required=True,
    type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True),
    help="Path to connector schema JSON file.",
)
@click.option(
    "--registry-file",
    "registry_file",
    default=".connectorguard_registry.json",
    show_default=True,
    help="Path to the local registry state file.",
)
def register_command(schema_path: str, registry_file: str) -> None:
    """Register a connector schema from a JSON file.

    The schema is merged into the local registry file (created if absent).

    \b
    Schema JSON example:
        {
          "name": "openai-chat",
          "version": "1.0.0",
          "rate_limit": 60,
          "required_permissions": ["llm:call"],
          "input_schema": {"type": "object", "required": ["prompt"]},
          "output_schema": {"type": "object"}
        }
    """
    try:
        raw = Path(schema_path).read_text(encoding="utf-8")
        data: Any = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        click.echo(click.style(f"error reading schema file: {exc}", fg="red"), err=True)
        sys.exit(1)

    try:
        schema = ConnectorSchema.model_validate(data)
    except Exception as exc:  # noqa: BLE001
        click.echo(click.style(f"invalid connector schema: {exc}", fg="red"), err=True)
        sys.exit(1)

    # Load existing registry state.
    registry_path = Path(registry_file)
    registry_data: dict[str, Any] = {}
    if registry_path.exists():
        try:
            registry_data = json.loads(registry_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001, S110
            pass  # Corrupt registry — start fresh rather than crashing.

    registry_data[schema.name] = schema.model_dump(mode="json")
    registry_path.write_text(json.dumps(registry_data, indent=2), encoding="utf-8")

    click.echo(
        click.style(
            f"Registered connector '{schema.name}' v{schema.version}"
            f" -> {registry_file}",
            fg="green",
        )
    )


# ---------------------------------------------------------------------------
# watch
# ---------------------------------------------------------------------------


@main.command("watch")
@click.option(
    "--agent",
    "agent_dir",
    required=True,
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    help="Agent directory to watch (scans for *.json connection log files).",
)
@click.option(
    "--registry-file",
    "registry_file",
    default=".connectorguard_registry.json",
    show_default=True,
    help="Path to the local registry state file.",
)
@click.option(
    "--agent-id",
    "agent_id",
    default="watched-agent",
    show_default=True,
    help="Agent identifier used for permission and rate-limit checks.",
)
def watch_command(agent_dir: str, registry_file: str, agent_id: str) -> None:
    """Watch an agent directory for connection log files and validate them.

    Reads all ``*.json`` files in *agent_dir* that match a connection attempt
    schema and validates each against registered connectors.
    """
    registry = _load_registry(registry_file)
    validator = ConnectionValidator(registry)
    audit_log = AuditLog()
    total = 0
    denied = 0

    agent_path = Path(agent_dir)
    log_files = list(agent_path.glob("*.json"))

    if not log_files:
        click.echo(f"No JSON log files found in {agent_dir}")
        return

    for log_file in sorted(log_files):
        try:
            raw = json.loads(log_file.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            click.echo(click.style(f"  [SKIP] {log_file.name}: {exc}", fg="yellow"))
            continue

        attempts = raw if isinstance(raw, list) else [raw]
        for entry in attempts:
            if not isinstance(entry, dict) or "connector_name" not in entry:
                continue
            entry.setdefault("source_agent", agent_id)

            try:
                attempt = ConnectionAttempt.model_validate(entry)
            except Exception as exc:  # noqa: BLE001
                click.echo(
                    click.style(
                        f"  [INVALID] {log_file.name}: {exc}",
                        fg="yellow",
                    )
                )
                continue

            result = validator.validate(attempt)
            audit_log.append(AuditEntry(connection_attempt=attempt, result=result))
            total += 1
            if not result.allowed:
                denied += 1

            color = "green" if result.allowed else "red"
            status = "ALLOW" if result.allowed else "DENY "
            click.echo(
                click.style(
                    f"  [{status}] {attempt.connector_name} "
                    f"(agent={attempt.source_agent}) — {result.reason}",
                    fg=color,
                )
            )

    click.echo(
        f"\nProcessed {total} attempt(s): {total - denied} allowed, {denied} denied."
    )


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


@main.command("audit")
@click.option(
    "--since",
    "since_spec",
    default="1h",
    show_default=True,
    help=(
        "Show entries from the last N seconds/minutes/hours"
        " (e.g. '30m', '2h', '3600s')."
    ),
)
@click.option(
    "--output",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
)
@click.option(
    "--log-file",
    "log_file",
    default=".connectorguard_audit.json",
    show_default=True,
    help="Path to the persistent audit log file.",
)
def audit_command(since_spec: str, output_format: str, log_file: str) -> None:
    """Show recent audit log entries.

    Reads from the persistent audit log written by other connectorguard
    operations.  When the file does not exist, prints a message and exits.
    """
    log_path = Path(log_file)
    if not log_path.exists():
        click.echo(f"Audit log not found: {log_file}")
        return

    try:
        raw_entries: Any = json.loads(log_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        click.echo(click.style(f"error reading audit log: {exc}", fg="red"), err=True)
        sys.exit(1)

    if not isinstance(raw_entries, list):
        click.echo(
            click.style(
                "audit log format error: expected JSON array",
                fg="red",
            ),
            err=True,
        )
        sys.exit(1)

    audit_log = AuditLog()
    for raw in raw_entries:
        try:
            audit_log.append(AuditEntry.model_validate(raw))
        except Exception:  # noqa: BLE001, S110
            pass  # Skip malformed entries rather than aborting the whole log.

    cutoff = datetime.datetime.now(datetime.UTC) - _parse_duration(since_spec)
    entries = audit_log.since(cutoff)

    if not entries:
        click.echo(f"No audit entries since {cutoff.isoformat()}")
        return

    if output_format == "json":
        click.echo(
            json.dumps(
                [e.model_dump(mode="json") for e in entries],
                indent=2,
                default=str,
            )
        )
        return

    click.echo(f"Audit log — {len(entries)} entries since {cutoff.isoformat()}")
    click.echo("-" * 70)
    for entry in entries:
        status = "ALLOW" if entry.result.allowed else "DENY "
        color = "green" if entry.result.allowed else "red"
        click.echo(
            click.style(
                f"  [{status}] {entry.timestamp.isoformat()} "
                f"connector={entry.connection_attempt.connector_name} "
                f"agent={entry.connection_attempt.source_agent} "
                f"— {entry.result.reason}",
                fg=color,
            )
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_registry(registry_file: str) -> ConnectorRegistry:
    registry = ConnectorRegistry()
    registry_path = Path(registry_file)
    if not registry_path.exists():
        return registry
    try:
        data: Any = json.loads(registry_path.read_text(encoding="utf-8"))
        for _name, schema_data in data.items():
            schema = ConnectorSchema.model_validate(schema_data)
            registry.register(schema)
    except Exception as exc:  # noqa: BLE001
        click.echo(
            click.style(
                f"warning: could not load registry '{registry_file}': {exc}",
                fg="yellow",
            ),
            err=True,
        )
    return registry


def _parse_duration(spec: str) -> datetime.timedelta:
    """Parse a duration string like '30m', '2h', '3600s' into a timedelta."""
    pattern = re.compile(r"^(\d+(?:\.\d+)?)\s*([smh]?)$", re.IGNORECASE)
    match = pattern.match(spec.strip())
    if not match:
        raise click.BadParameter(
            f"Invalid duration '{spec}'."
            " Expected format: <number>[s|m|h], e.g. '30m', '2h', '3600s'."
        )
    value = float(match.group(1))
    unit = match.group(2).lower()
    multiplier = {"s": 1, "m": 60, "h": 3600, "": 1}
    return datetime.timedelta(seconds=value * multiplier[unit])


if __name__ == "__main__":
    main()
