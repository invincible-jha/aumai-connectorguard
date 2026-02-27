"""Tests for aumai_connectorguard.cli."""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from aumai_connectorguard.cli import _parse_duration, main

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def _make_valid_schema_dict(
    name: str = "openai-chat",
    version: str = "1.0.0",
    rate_limit: int = 60,
    required_permissions: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "version": version,
        "rate_limit": rate_limit,
        "required_permissions": required_permissions or [],
        "input_schema": {},
        "output_schema": {},
    }


def _register_args(schema_file: Path, registry_file: Path) -> list[str]:
    """Build CLI args for the register command."""
    return [
        "register",
        "--schema",
        str(schema_file),
        "--registry-file",
        str(registry_file),
    ]


def _watch_args(
    agent_dir: Path,
    registry_file: Path,
    agent_id: str | None = None,
) -> list[str]:
    """Build CLI args for the watch command."""
    args = [
        "watch",
        "--agent",
        str(agent_dir),
        "--registry-file",
        str(registry_file),
    ]
    if agent_id is not None:
        args += ["--agent-id", agent_id]
    return args


def _audit_args(
    log_file: Path,
    since: str = "1h",
    output: str = "text",
) -> list[str]:
    """Build CLI args for the audit command."""
    return [
        "audit",
        "--log-file",
        str(log_file),
        "--since",
        since,
        "--output",
        output,
    ]


# ---------------------------------------------------------------------------
# Version flag (already in stub — extended)
# ---------------------------------------------------------------------------


class TestVersionFlag:
    def test_cli_version_exits_zero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0

    def test_cli_version_contains_version_string(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert "0.1.0" in result.output


# ---------------------------------------------------------------------------
# register command
# ---------------------------------------------------------------------------


class TestRegisterCommand:
    def test_register_creates_registry_file(self, tmp_path: Path) -> None:
        schema_file = tmp_path / "schema.json"
        registry_file = tmp_path / "registry.json"
        _write_json(schema_file, _make_valid_schema_dict())

        runner = CliRunner()
        result = runner.invoke(main, _register_args(schema_file, registry_file))
        assert result.exit_code == 0, result.output
        assert registry_file.exists()

    def test_register_writes_connector_to_registry(self, tmp_path: Path) -> None:
        schema_file = tmp_path / "schema.json"
        registry_file = tmp_path / "registry.json"
        _write_json(schema_file, _make_valid_schema_dict(name="my-tool"))

        runner = CliRunner()
        runner.invoke(main, _register_args(schema_file, registry_file))
        stored = json.loads(registry_file.read_text())
        assert "my-tool" in stored

    def test_register_success_message_contains_name(self, tmp_path: Path) -> None:
        schema_file = tmp_path / "schema.json"
        registry_file = tmp_path / "registry.json"
        _write_json(
            schema_file, _make_valid_schema_dict(name="my-tool", version="2.3.0")
        )

        runner = CliRunner()
        result = runner.invoke(main, _register_args(schema_file, registry_file))
        assert "my-tool" in result.output

    def test_register_success_message_contains_version(self, tmp_path: Path) -> None:
        schema_file = tmp_path / "schema.json"
        registry_file = tmp_path / "registry.json"
        _write_json(schema_file, _make_valid_schema_dict(version="3.1.4"))

        runner = CliRunner()
        result = runner.invoke(main, _register_args(schema_file, registry_file))
        assert "3.1.4" in result.output

    def test_register_merges_into_existing_registry(self, tmp_path: Path) -> None:
        registry_file = tmp_path / "registry.json"
        # Pre-populate registry with one connector
        _write_json(
            registry_file,
            {"existing-tool": _make_valid_schema_dict(name="existing-tool")},
        )

        schema_file = tmp_path / "schema.json"
        _write_json(schema_file, _make_valid_schema_dict(name="new-tool"))

        runner = CliRunner()
        runner.invoke(main, _register_args(schema_file, registry_file))
        stored = json.loads(registry_file.read_text())
        assert "existing-tool" in stored
        assert "new-tool" in stored

    def test_register_missing_schema_file_exits_nonzero(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "register",
                "--schema",
                str(tmp_path / "nonexistent.json"),
                "--registry-file",
                str(tmp_path / "reg.json"),
            ],
        )
        assert result.exit_code != 0

    def test_register_invalid_json_exits_with_error(self, tmp_path: Path) -> None:
        schema_file = tmp_path / "bad.json"
        schema_file.write_text("this is not json", encoding="utf-8")
        registry_file = tmp_path / "registry.json"

        runner = CliRunner()
        result = runner.invoke(main, _register_args(schema_file, registry_file))
        assert result.exit_code == 1

    def test_register_invalid_schema_exits_with_error(self, tmp_path: Path) -> None:
        schema_file = tmp_path / "schema.json"
        # Missing required fields "name" and "version"
        _write_json(schema_file, {"rate_limit": 10})
        registry_file = tmp_path / "registry.json"

        runner = CliRunner()
        result = runner.invoke(main, _register_args(schema_file, registry_file))
        assert result.exit_code == 1

    def test_register_uses_default_registry_filename(self, tmp_path: Path) -> None:
        schema_file = tmp_path / "schema.json"
        _write_json(schema_file, _make_valid_schema_dict())

        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(
                main, ["register", "--schema", str(schema_file)]
            )
            assert result.exit_code == 0
            assert Path(".connectorguard_registry.json").exists()

    def test_register_schema_with_required_permissions(self, tmp_path: Path) -> None:
        schema_file = tmp_path / "schema.json"
        _write_json(
            schema_file,
            _make_valid_schema_dict(
                name="secured-tool",
                required_permissions=["admin:write", "data:read"],
            ),
        )
        registry_file = tmp_path / "registry.json"

        runner = CliRunner()
        result = runner.invoke(main, _register_args(schema_file, registry_file))
        assert result.exit_code == 0
        stored = json.loads(registry_file.read_text())
        assert stored["secured-tool"]["required_permissions"] == [
            "admin:write",
            "data:read",
        ]


# ---------------------------------------------------------------------------
# watch command
# ---------------------------------------------------------------------------


class TestWatchCommand:
    def test_watch_empty_directory_prints_no_files_message(
        self, tmp_path: Path
    ) -> None:
        agent_dir = tmp_path / "agent_logs"
        agent_dir.mkdir()

        runner = CliRunner()
        result = runner.invoke(
            main,
            _watch_args(agent_dir, tmp_path / "reg.json"),
        )
        assert result.exit_code == 0
        assert "No JSON log files" in result.output

    def test_watch_processes_connection_log(self, tmp_path: Path) -> None:
        registry_file = tmp_path / "registry.json"
        _write_json(registry_file, {"my-tool": _make_valid_schema_dict(name="my-tool")})

        agent_dir = tmp_path / "agent_logs"
        agent_dir.mkdir()
        log_file = agent_dir / "attempt.json"
        _write_json(log_file, {"connector_name": "my-tool", "input_data": {}})

        runner = CliRunner()
        result = runner.invoke(
            main,
            _watch_args(agent_dir, registry_file, agent_id="test-agent"),
        )
        assert result.exit_code == 0
        assert "my-tool" in result.output

    def test_watch_reports_totals(self, tmp_path: Path) -> None:
        registry_file = tmp_path / "registry.json"
        _write_json(registry_file, {"my-tool": _make_valid_schema_dict(name="my-tool")})

        agent_dir = tmp_path / "agent_logs"
        agent_dir.mkdir()
        _write_json(agent_dir / "a.json", {"connector_name": "my-tool"})
        _write_json(agent_dir / "b.json", {"connector_name": "my-tool"})

        runner = CliRunner()
        result = runner.invoke(main, _watch_args(agent_dir, registry_file))
        assert "2" in result.output  # Processed 2 attempts

    def test_watch_logs_allow_for_registered_connector(self, tmp_path: Path) -> None:
        registry_file = tmp_path / "registry.json"
        _write_json(registry_file, {"my-tool": _make_valid_schema_dict(name="my-tool")})

        agent_dir = tmp_path / "agent_logs"
        agent_dir.mkdir()
        _write_json(agent_dir / "a.json", {"connector_name": "my-tool"})

        runner = CliRunner()
        result = runner.invoke(main, _watch_args(agent_dir, registry_file))
        assert "ALLOW" in result.output

    def test_watch_logs_deny_for_unregistered_connector(self, tmp_path: Path) -> None:
        registry_file = tmp_path / "registry.json"
        _write_json(registry_file, {})  # empty registry

        agent_dir = tmp_path / "agent_logs"
        agent_dir.mkdir()
        _write_json(agent_dir / "a.json", {"connector_name": "unknown-tool"})

        runner = CliRunner()
        result = runner.invoke(main, _watch_args(agent_dir, registry_file))
        assert "DENY" in result.output

    def test_watch_skips_invalid_json_files(self, tmp_path: Path) -> None:
        registry_file = tmp_path / "registry.json"
        _write_json(registry_file, {})

        agent_dir = tmp_path / "agent_logs"
        agent_dir.mkdir()
        (agent_dir / "bad.json").write_text("not json", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(main, _watch_args(agent_dir, registry_file))
        assert result.exit_code == 0
        assert "SKIP" in result.output

    def test_watch_skips_entries_without_connector_name(self, tmp_path: Path) -> None:
        registry_file = tmp_path / "registry.json"
        _write_json(registry_file, {})

        agent_dir = tmp_path / "agent_logs"
        agent_dir.mkdir()
        _write_json(agent_dir / "a.json", {"no_connector_key": "value"})

        runner = CliRunner()
        result = runner.invoke(main, _watch_args(agent_dir, registry_file))
        assert result.exit_code == 0

    def test_watch_processes_list_of_attempts_from_file(self, tmp_path: Path) -> None:
        registry_file = tmp_path / "registry.json"
        _write_json(registry_file, {"my-tool": _make_valid_schema_dict(name="my-tool")})

        agent_dir = tmp_path / "agent_logs"
        agent_dir.mkdir()
        _write_json(
            agent_dir / "multi.json",
            [
                {"connector_name": "my-tool"},
                {"connector_name": "my-tool"},
                {"connector_name": "my-tool"},
            ],
        )

        runner = CliRunner()
        result = runner.invoke(main, _watch_args(agent_dir, registry_file))
        assert "3" in result.output

    def test_watch_uses_default_registry_when_file_missing(
        self, tmp_path: Path
    ) -> None:
        agent_dir = tmp_path / "agent_logs"
        agent_dir.mkdir()
        _write_json(agent_dir / "a.json", {"connector_name": "my-tool"})

        runner = CliRunner()
        result = runner.invoke(
            main,
            _watch_args(agent_dir, tmp_path / "nonexistent_reg.json"),
        )
        # Should complete without crashing; connector will be unregistered -> DENY
        assert result.exit_code == 0

    def test_watch_applies_agent_id_option(self, tmp_path: Path) -> None:
        registry_file = tmp_path / "registry.json"
        _write_json(registry_file, {"my-tool": _make_valid_schema_dict(name="my-tool")})

        agent_dir = tmp_path / "agent_logs"
        agent_dir.mkdir()
        _write_json(agent_dir / "a.json", {"connector_name": "my-tool"})

        runner = CliRunner()
        result = runner.invoke(
            main,
            _watch_args(agent_dir, registry_file, agent_id="custom-agent-99"),
        )
        assert "custom-agent-99" in result.output


# ---------------------------------------------------------------------------
# audit command
# ---------------------------------------------------------------------------


class TestAuditCommand:
    def _make_audit_entry_dict(
        self, connector: str = "my-tool", allowed: bool = True
    ) -> dict[str, Any]:
        now_str = datetime.datetime.now(datetime.UTC).isoformat()
        return {
            "connection_attempt": {
                "connector_name": connector,
                "source_agent": "agent-1",
                "input_data": {},
                "timestamp": now_str,
            },
            "result": {
                "allowed": allowed,
                "reason": "all checks passed" if allowed else "denied",
                "latency_ms": 1.5,
            },
            "timestamp": now_str,
        }

    def test_audit_missing_log_file_prints_message(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["audit", "--log-file", str(tmp_path / "nonexistent_audit.json")],
        )
        assert result.exit_code == 0
        assert "not found" in result.output

    def test_audit_empty_list_prints_no_entries(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.json"
        _write_json(log_file, [])

        runner = CliRunner()
        result = runner.invoke(main, _audit_args(log_file))
        assert result.exit_code == 0
        assert "No audit entries" in result.output

    def test_audit_text_format_shows_entries(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.json"
        _write_json(log_file, [self._make_audit_entry_dict()])

        runner = CliRunner()
        result = runner.invoke(main, _audit_args(log_file, output="text"))
        assert result.exit_code == 0
        assert "my-tool" in result.output

    def test_audit_json_format_outputs_parseable_json(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.json"
        _write_json(log_file, [self._make_audit_entry_dict()])

        runner = CliRunner()
        result = runner.invoke(main, _audit_args(log_file, output="json"))
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)
        assert len(parsed) >= 1

    def test_audit_invalid_json_exits_with_error(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.json"
        log_file.write_text("not valid json", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["audit", "--log-file", str(log_file)],
        )
        assert result.exit_code == 1

    def test_audit_non_array_json_exits_with_error(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.json"
        _write_json(log_file, {"not": "an array"})

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["audit", "--log-file", str(log_file)],
        )
        assert result.exit_code == 1

    def test_audit_filters_by_since_spec(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.json"
        old_entry = self._make_audit_entry_dict()
        # Backdate the timestamp far into the past
        old_entry["timestamp"] = "2020-01-01T00:00:00+00:00"
        old_entry["connection_attempt"]["timestamp"] = "2020-01-01T00:00:00+00:00"
        recent_entry = self._make_audit_entry_dict(connector="recent-tool")
        _write_json(log_file, [old_entry, recent_entry])

        runner = CliRunner()
        result = runner.invoke(main, _audit_args(log_file))
        assert "recent-tool" in result.output
        # The 2020 entry should be filtered out
        assert (
            result.output.count("my-tool") == 0 or "recent-tool" in result.output
        )

    def test_audit_text_output_shows_allow_status(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.json"
        _write_json(log_file, [self._make_audit_entry_dict(allowed=True)])

        runner = CliRunner()
        result = runner.invoke(main, _audit_args(log_file, output="text"))
        assert "ALLOW" in result.output

    def test_audit_text_output_shows_deny_status(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.json"
        _write_json(log_file, [self._make_audit_entry_dict(allowed=False)])

        runner = CliRunner()
        result = runner.invoke(main, _audit_args(log_file, output="text"))
        assert "DENY" in result.output

    def test_audit_skips_malformed_entries_gracefully(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.json"
        _write_json(
            log_file,
            [
                {"this": "is not an audit entry"},
                self._make_audit_entry_dict(),
            ],
        )

        runner = CliRunner()
        result = runner.invoke(main, _audit_args(log_file))
        # Should not crash
        assert result.exit_code == 0

    def test_audit_uses_default_since_one_hour(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.json"
        _write_json(log_file, [self._make_audit_entry_dict()])

        runner = CliRunner()
        result = runner.invoke(main, ["audit", "--log-file", str(log_file)])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# _parse_duration helper
# ---------------------------------------------------------------------------


class TestParseDuration:
    def test_seconds_suffix(self) -> None:
        delta = _parse_duration("3600s")
        assert delta == datetime.timedelta(seconds=3600)

    def test_minutes_suffix(self) -> None:
        delta = _parse_duration("30m")
        assert delta == datetime.timedelta(minutes=30)

    def test_hours_suffix(self) -> None:
        delta = _parse_duration("2h")
        assert delta == datetime.timedelta(hours=2)

    def test_uppercase_suffix(self) -> None:
        delta = _parse_duration("5H")
        assert delta == datetime.timedelta(hours=5)

    def test_numeric_only_defaults_to_seconds(self) -> None:
        delta = _parse_duration("120")
        assert delta == datetime.timedelta(seconds=120)

    def test_float_value(self) -> None:
        delta = _parse_duration("1.5h")
        assert delta == datetime.timedelta(hours=1.5)

    def test_invalid_format_raises(self) -> None:
        import click

        with pytest.raises(click.BadParameter):
            _parse_duration("invalid")

    def test_invalid_unit_raises(self) -> None:
        import click

        with pytest.raises(click.BadParameter):
            _parse_duration("10d")

    def test_whitespace_stripped(self) -> None:
        delta = _parse_duration("  60m  ")
        assert delta == datetime.timedelta(minutes=60)

    def test_one_second(self) -> None:
        delta = _parse_duration("1s")
        assert delta == datetime.timedelta(seconds=1)

    def test_zero_seconds(self) -> None:
        delta = _parse_duration("0s")
        assert delta == datetime.timedelta(seconds=0)
