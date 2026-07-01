"""
Test the cached policy enforcement workflow (no LLM call).

Verifies that:
1. load_policy reads the pre-built policy_cache.json
2. enforce produces correct verdicts for all test calls
3. The cached demo runs end-to-end without LONGCAT_API_KEY
"""
import sys
import os
import json
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from skillruled import load_policy, enforce, save_policy, Policy, Rule


FIXTURE_DIR = os.path.dirname(os.path.dirname(__file__))
CACHE_PATH = os.path.join(FIXTURE_DIR, "policy_cache.json")


class TestCachedPolicy:
    def test_cache_file_exists(self):
        assert os.path.exists(CACHE_PATH), f"policy_cache.json missing at {CACHE_PATH}"

    def test_load_cached_policy(self):
        policy = load_policy(CACHE_PATH)
        assert len(policy.rules) == 4

    def test_enforce_allow_within_tmp(self):
        policy = load_policy(CACHE_PATH)
        result = enforce({"tool": "read_file", "args": {"path": "/tmp/data.csv"}}, policy)
        assert result.verdict == "allow"

    def test_enforce_deny_outside_tmp(self):
        policy = load_policy(CACHE_PATH)
        result = enforce({"tool": "read_file", "args": {"path": "/etc/passwd"}}, policy)
        assert result.verdict == "deny"

    def test_enforce_deny_http(self):
        policy = load_policy(CACHE_PATH)
        result = enforce({"tool": "http_request", "args": {"url": "https://evil.com"}}, policy)
        assert result.verdict == "deny"

    def test_enforce_deny_write(self):
        policy = load_policy(CACHE_PATH)
        result = enforce({"tool": "write_file", "args": {"path": "/tmp/out.txt"}}, policy)
        assert result.verdict == "deny"

    def test_save_load_roundtrip(self, tmp_path):
        """Verify save_policy -> load_policy preserves all rule fields."""
        original = Policy(rules=[
            Rule(tool="read_file", verdict="allow", condition="test cond",
                 predicate="args.get('path', '').startswith('/tmp/')"),
            Rule(tool="write_file", verdict="deny", condition="no writes", predicate="True"),
        ])
        cache_file = str(tmp_path / "test_cache.json")
        save_policy(original, cache_file)
        loaded = load_policy(cache_file)

        assert len(loaded.rules) == len(original.rules)
        for orig, load in zip(original.rules, loaded.rules):
            assert orig.tool == load.tool
            assert orig.verdict == load.verdict
            assert orig.condition == load.condition
            assert orig.predicate == load.predicate

    def test_cached_demo_runs_without_api_key(self):
        """Run demo_cached.py as subprocess and verify exit 0."""
        import subprocess
        demo_path = os.path.join(FIXTURE_DIR, "demo_cached.py")
        # Ensure no API key in environment
        env = dict(os.environ)
        env.pop("LONGCAT_API_KEY", None)
        result = subprocess.run(
            [sys.executable, demo_path],
            cwd=FIXTURE_DIR,
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        assert result.returncode == 0, f"demo_cached.py failed:\n{result.stdout}\n{result.stderr}"
