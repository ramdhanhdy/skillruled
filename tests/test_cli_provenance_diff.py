"""
Tests for CLI (B1), boundary provenance (B2), and diff (B3).

B1: skillruled compile + skillruled enforce CLI
B2: EnforcementResult includes source_text from the SKILL.md boundary
B3: diff_policy shows compiled rules with source provenance
"""
import sys
import os
import json
import subprocess
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from skillruled import (
    enforce, load_policy, save_policy, diff_policy,
    Policy, Rule, EnforcementResult,
)

FIXTURE_DIR = os.path.dirname(os.path.dirname(__file__))
CACHE_PATH = os.path.join(FIXTURE_DIR, "policy_cache.json")


# ── B2: Boundary Provenance ───────────────────────────────────────

class TestProvenance:
    def test_enforce_returns_source_text(self):
        """EnforcementResult should include source_text from the matching rule."""
        policy = load_policy(CACHE_PATH)
        result = enforce({"tool": "read_file", "args": {"path": "/tmp/data.csv"}}, policy)
        assert result.verdict == "allow"
        assert result.source_text == "Only read files under /tmp/."

    def test_enforce_deny_has_source_text(self):
        policy = load_policy(CACHE_PATH)
        result = enforce({"tool": "read_file", "args": {"path": "/etc/passwd"}}, policy)
        assert result.verdict == "deny"
        assert result.source_text == "Only read files under /tmp/."

    def test_http_deny_has_source_text(self):
        policy = load_policy(CACHE_PATH)
        result = enforce({"tool": "http_request", "args": {"url": "https://evil.com"}}, policy)
        assert result.verdict == "deny"
        assert result.source_text == "Never make HTTP requests."

    def test_default_deny_has_empty_source(self):
        """Default deny (no matching rule) should have empty source_text."""
        policy = load_policy(CACHE_PATH)
        result = enforce({"tool": "unknown_tool", "args": {}}, policy)
        assert result.verdict == "deny"
        assert result.source_text == ""

    def test_save_load_preserves_source_text(self, tmp_path):
        """save_policy / load_policy should roundtrip source_text."""
        policy = Policy(rules=[
            Rule(tool="test", verdict="allow", condition="ok",
                 predicate="True", source_text="May do test operations."),
        ])
        path = str(tmp_path / "test.json")
        save_policy(policy, path)
        loaded = load_policy(path)
        assert loaded.rules[0].source_text == "May do test operations."


# ── B3: Diff ──────────────────────────────────────────────────────

class TestDiff:
    def test_diff_shows_rules(self):
        policy = load_policy(CACHE_PATH)
        output = diff_policy(policy)
        assert "4 rules compiled" in output
        assert "read_file" in output
        assert "http_request" in output

    def test_diff_shows_source_text(self):
        policy = load_policy(CACHE_PATH)
        output = diff_policy(policy)
        assert "Only read files under /tmp/" in output
        assert "Never make HTTP requests" in output

    def test_diff_shows_predicates(self):
        policy = load_policy(CACHE_PATH)
        output = diff_policy(policy)
        assert "args.get('path', '').startswith('/tmp/')" in output
        assert "True" in output

    def test_diff_empty_policy(self):
        policy = Policy(rules=[])
        output = diff_policy(policy)
        assert "No rules compiled" in output

    def test_diff_handles_missing_source_text(self):
        policy = Policy(rules=[
            Rule(tool="test", verdict="allow", condition="ok", predicate="True"),
        ])
        output = diff_policy(policy)
        assert "no source text recorded" in output


# ── B1: CLI ───────────────────────────────────────────────────────

class TestCLI:
    def test_cli_diff(self):
        """skillruled diff <policy.json> should print rules with provenance."""
        result = subprocess.run(
            [sys.executable, "-c", f"import skillruled; skillruled.cli()",
             "diff", CACHE_PATH],
            capture_output=True, text=True, timeout=10,
            cwd=FIXTURE_DIR,
        )
        assert result.returncode == 0
        assert "4 rules compiled" in result.stdout
        assert "Only read files under /tmp/" in result.stdout

    def test_cli_enforce_allow(self):
        """skillruled enforce --policy policy.json --tool read_file --args '{"path":"/tmp/data.csv"}'"""
        result = subprocess.run(
            [sys.executable, "-c", f"import skillruled; skillruled.cli()",
             "enforce",
             "--policy", CACHE_PATH,
             "--tool", "read_file",
             "--args", '{"path": "/tmp/data.csv"}'],
            capture_output=True, text=True, timeout=10,
            cwd=FIXTURE_DIR,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["verdict"] == "allow"
        assert data["source_text"] == "Only read files under /tmp/."

    def test_cli_enforce_deny(self):
        """skillruled enforce should exit 2 on deny."""
        result = subprocess.run(
            [sys.executable, "-c", f"import skillruled; skillruled.cli()",
             "enforce",
             "--policy", CACHE_PATH,
             "--tool", "read_file",
             "--args", '{"path": "/etc/passwd"}'],
            capture_output=True, text=True, timeout=10,
            cwd=FIXTURE_DIR,
        )
        assert result.returncode == 2
        data = json.loads(result.stdout)
        assert data["verdict"] == "deny"
        assert data["source_text"] == "Only read files under /tmp/."

    def test_cli_enforce_json_output(self):
        """enforce output should be valid JSON with verdict, reason, source_text."""
        result = subprocess.run(
            [sys.executable, "-c", f"import skillruled; skillruled.cli()",
             "enforce",
             "--policy", CACHE_PATH,
             "--tool", "http_request",
             "--args", '{"url": "https://evil.com"}'],
            capture_output=True, text=True, timeout=10,
            cwd=FIXTURE_DIR,
        )
        data = json.loads(result.stdout)
        assert set(data.keys()) == {"verdict", "reason", "source_text"}
        assert data["verdict"] == "deny"
        assert data["source_text"] == "Never make HTTP requests."

    def test_cli_no_args(self):
        """skillruled with no args should print usage and exit 1."""
        result = subprocess.run(
            [sys.executable, "-c", f"import skillruled; skillruled.cli()"],
            capture_output=True, text=True, timeout=10,
            cwd=FIXTURE_DIR,
        )
        assert result.returncode == 1
        assert "usage" in result.stdout.lower()
