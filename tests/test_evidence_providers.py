#!/usr/bin/env python3
"""Tests for scripts/run_evidence_providers.py — evidence-provider wrapper."""

import json
import os
import subprocess
import sys
from pathlib import Path

# Ensure the scripts directory is on sys.path before any imports.
_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import pytest


EVIDENCE_SCRIPT = _SCRIPTS_DIR / "run_evidence_providers.py"

# Helper scripts written into tmp dirs by tests.
HELPER_JSON_FINDINGS = """\
#!/usr/bin/env python3
import json, sys
data = {"severity": "warning", "findings": [{"message": "test finding", "severity": "warning"}]}
json.dump(data, sys.stdout)
"""

HELPER_BLOCKER = """\
#!/usr/bin/env python3
import json, sys
data = {"severity": "blocker", "findings": [{"message": "critical issue", "severity": "blocker"}]}
json.dump(data, sys.stdout)
"""

HELPER_MIXED = """\
#!/usr/bin/env python3
import json, sys
data = {"severity": "warning", "findings": [
    {"message": "low", "severity": "info"},
    {"message": "high", "severity": "blocker"}
]}
json.dump(data, sys.stdout)
"""

HELPER_SECRET_STDOUT = """\
#!/usr/bin/env python3
print("api_key=sk-secret_value_1234567890")
"""

HELPER_SECRET_STDERR = """\
#!/usr/bin/env python3
import sys
sys.stderr.write("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\\n")
"""


def _run_with_config(config_data, tmp_path: Path) -> subprocess.CompletedProcess:
    """Helper: write config, run the script, return CompletedProcess."""
    config_file = tmp_path / "providers.json"
    config_file.write_text(json.dumps(config_data, indent=2), encoding="utf-8")

    env = os.environ.copy()
    env["EVIDENCE_PROVIDERS_FILE"] = str(config_file)

    result = subprocess.run(
        [sys.executable, str(EVIDENCE_SCRIPT)],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result


def _load_json_output(tmp_path: Path) -> dict:
    out = (tmp_path / "evidence-providers.json").read_text(encoding="utf-8")
    return json.loads(out)


# ---------------------------------------------------------------------------
# No providers configured
# ---------------------------------------------------------------------------


class TestNoConfig:
    def test_empty_env(self, tmp_path: Path):
        """When config is empty dict, the script still parses it and sets configured=True."""
        result = _run_with_config({}, tmp_path)
        assert result.returncode == 0
        data = _load_json_output(tmp_path)
        # An empty config dict is still a valid config; providers list is just empty.
        assert data["configured"] is True
        assert data["provider_count"] == 0

    def test_missing_config_file(self, tmp_path: Path):
        env = os.environ.copy()
        env["EVIDENCE_PROVIDERS_FILE"] = str(tmp_path / "nonexistent.json")
        result = subprocess.run(
            [sys.executable, str(EVIDENCE_SCRIPT)],
            cwd=str(tmp_path),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        data = _load_json_output(tmp_path)
        assert "error" in data
        assert "not found" in data["error"]


# ---------------------------------------------------------------------------
# stdout capture — bytes → string decode fix
# ---------------------------------------------------------------------------


class TestStdoutCapture:
    """Verify that provider stdout is decoded from bytes to str before redaction."""

    def test_json_stdout_with_findings(self, tmp_path: Path):
        helper = tmp_path / "json_provider.py"
        helper.write_text(HELPER_JSON_FINDINGS)

        config = {
            "providers": [
                {"id": "test-json", "command": f"{sys.executable} {helper}"}
            ]
        }
        result = _run_with_config(config, tmp_path)
        assert result.returncode == 0, f"stderr: {result.stderr}"
        data = _load_json_output(tmp_path)
        assert data["configured"] is True
        assert len(data["providers"]) == 1
        p = data["providers"][0]
        assert p["status"] == "ok"
        assert p["output_format"] == "json"
        assert len(p["findings"]) == 1
        assert p["findings"][0]["message"] == "test finding"

    def test_text_stdout_no_findings(self, tmp_path: Path):
        config = {
            "providers": [
                {"id": "test-text", "command": "echo 'just some text output'"}
            ]
        }
        result = _run_with_config(config, tmp_path)
        assert result.returncode == 0
        data = _load_json_output(tmp_path)
        p = data["providers"][0]
        assert p["status"] == "ok"
        assert p["output_format"] == "text"
        assert "just some text output" in p["stdout"]


# ---------------------------------------------------------------------------
# stderr capture
# ---------------------------------------------------------------------------


class TestStderrCapture:
    def test_stderr_is_captured(self, tmp_path: Path):
        helper = tmp_path / "stderr_provider.py"
        helper.write_text(HELPER_SECRET_STDERR)

        config = {"providers": [{"id": "test-stderr", "command": f"{sys.executable} {helper}"}]}
        result = _run_with_config(config, tmp_path)
        assert result.returncode == 0
        data = _load_json_output(tmp_path)
        p = data["providers"][0]
        assert p["status"] == "ok"
        assert "[REDACTED]" in p["stderr"]

    def test_stderr_only_provider(self, tmp_path: Path):
        config = {
            "providers": [
                {"id": "test-stderr-only", "command": 'echo "no stdout, only stderr" >&2; exit 0'}
            ]
        }
        result = _run_with_config(config, tmp_path)
        assert result.returncode == 0
        data = _load_json_output(tmp_path)
        p = data["providers"][0]
        assert p["stderr"].strip() == "no stdout, only stderr"


# ---------------------------------------------------------------------------
# Silent provider — no output at all (verifies UnboundLocalError fix)
# ---------------------------------------------------------------------------


class TestSilentProvider:
    def test_silent_provider_no_crash(self, tmp_path: Path):
        """A provider that produces no stdout or stderr must not raise UnboundLocalError."""
        config = {
            "providers": [
                {"id": "test-silent", "command": "true"}  # does nothing, exits 0
            ]
        }
        result = _run_with_config(config, tmp_path)
        assert result.returncode == 0, f"stderr: {result.stderr}"
        data = _load_json_output(tmp_path)
        p = data["providers"][0]
        assert p["status"] == "ok"
        assert p["stdout"].strip() == ""
        assert p["stderr"].strip() == ""

    def test_silent_providers_list(self, tmp_path: Path):
        """Multiple silent providers should all complete without error."""
        config = {
            "providers": [
                {"id": "s1", "command": "true"},
                {"id": "s2", "command": "echo -n ''"},
            ]
        }
        result = _run_with_config(config, tmp_path)
        assert result.returncode == 0
        data = _load_json_output(tmp_path)
        assert len(data["providers"]) == 2
        for p in data["providers"]:
            assert p["status"] == "ok"


# ---------------------------------------------------------------------------
# Nonzero exit code
# ---------------------------------------------------------------------------


class TestNonzeroExit:
    def test_nonzero_exit_status(self, tmp_path: Path):
        config = {
            "providers": [
                {"id": "test-fail", "command": "exit 42"}
            ]
        }
        result = _run_with_config(config, tmp_path)
        assert result.returncode == 0  # wrapper itself should succeed
        data = _load_json_output(tmp_path)
        p = data["providers"][0]
        assert p["status"] == "error"
        assert p["exit_code"] == 42

    def test_command_that_exits_nonzero(self, tmp_path: Path):
        config = {
            "providers": [
                {"id": "test-fail-echo", "command": 'echo "failed"; exit 1'}
            ]
        }
        result = _run_with_config(config, tmp_path)
        assert result.returncode == 0
        data = _load_json_output(tmp_path)
        p = data["providers"][0]
        assert p["status"] == "error"
        assert p["exit_code"] == 1


# ---------------------------------------------------------------------------
# Blocker provider
# ---------------------------------------------------------------------------


class TestBlockerProvider:
    def test_blocker_severity_sets_flag(self, tmp_path: Path):
        helper = tmp_path / "blocker_provider.py"
        helper.write_text(HELPER_BLOCKER)

        config = {
            "providers": [
                {"id": "test-blocker", "command": f"{sys.executable} {helper}"}
            ]
        }
        result = _run_with_config(config, tmp_path)
        assert result.returncode == 0
        data = _load_json_output(tmp_path)
        assert data["has_blocker"] is True
        p = data["providers"][0]
        assert p["provider_severity"] == "blocker"

    def test_mixed_severities_uses_highest(self, tmp_path: Path):
        helper = tmp_path / "mixed_provider.py"
        helper.write_text(HELPER_MIXED)

        config = {
            "providers": [
                {"id": "test-mixed", "command": f"{sys.executable} {helper}"}
            ]
        }
        result = _run_with_config(config, tmp_path)
        assert result.returncode == 0
        data = _load_json_output(tmp_path)
        p = data["providers"][0]
        assert p["provider_severity"] == "blocker"


# ---------------------------------------------------------------------------
# Secret redaction on provider output
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_stdout_secrets_redacted(self, tmp_path: Path):
        helper = tmp_path / "secret_stdout.py"
        helper.write_text(HELPER_SECRET_STDOUT)

        config = {
            "providers": [
                {"id": "test-redact", "command": f"{sys.executable} {helper}"}
            ]
        }
        result = _run_with_config(config, tmp_path)
        assert result.returncode == 0
        data = _load_json_output(tmp_path)
        p = data["providers"][0]
        assert "sk-secret_value_1234567890" not in p["stdout"]
        assert "[REDACTED]" in p["stdout"]

    def test_stderr_secrets_redacted(self, tmp_path: Path):
        helper = tmp_path / "secret_stderr.py"
        helper.write_text(HELPER_SECRET_STDERR)

        config = {
            "providers": [
                {"id": "test-stderr-redact", "command": f"{sys.executable} {helper}"}
            ]
        }
        result = _run_with_config(config, tmp_path)
        assert result.returncode == 0
        data = _load_json_output(tmp_path)
        p = data["providers"][0]
        assert "ghp_" not in p["stderr"]
        assert "[REDACTED]" in p["stderr"]


# ---------------------------------------------------------------------------
# Markdown output file is generated
# ---------------------------------------------------------------------------


class TestMarkdownOutput:
    def test_markdown_file_created(self, tmp_path: Path):
        config = {
            "providers": [
                {"id": "test-md", "command": "echo 'hello'"}
            ]
        }
        result = _run_with_config(config, tmp_path)
        assert result.returncode == 0
        md_file = tmp_path / "evidence-providers.md"
        assert md_file.exists()
        content = md_file.read_text(encoding="utf-8")
        assert "test-md" in content

    def test_markdown_redacted(self, tmp_path: Path):
        helper = tmp_path / "secret_md.py"
        helper.write_text(HELPER_SECRET_STDOUT)

        config = {
            "providers": [
                {"id": "test-md-redact", "command": f"{sys.executable} {helper}"}
            ]
        }
        result = _run_with_config(config, tmp_path)
        assert result.returncode == 0
        md_file = tmp_path / "evidence-providers.md"
        content = md_file.read_text(encoding="utf-8")
        assert "super_secret_value_xyz123" not in content  # helper doesn't output this
        assert "[REDACTED]" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
