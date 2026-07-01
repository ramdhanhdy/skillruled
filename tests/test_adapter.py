"""
Tests for SkillGuardedTool adapter (B4).

Verifies that:
1. Allowed tool calls execute the function body
2. Denied tool calls raise PermissionError before execution
3. The decorator preserves function metadata
4. Both policy_cache and policy object construction work
5. PermissionError includes source_text provenance
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from skillruled import SkillGuardedTool, Policy, Rule, load_policy

FIXTURE_DIR = os.path.dirname(os.path.dirname(__file__))
CACHE_PATH = os.path.join(FIXTURE_DIR, "policy_cache.json")


class TestSkillGuardedTool:
    def setup_method(self):
        self.guarded = SkillGuardedTool(policy_cache=CACHE_PATH)

        @self.guarded
        def read_file(path: str) -> str:
            return f"content of {path}"

        @self.guarded
        def write_file(path: str, content: str = "") -> str:
            return f"wrote {path}"

        @self.guarded
        def http_request(url: str) -> str:
            return f"response from {url}"

        self.read_file = read_file
        self.write_file = write_file
        self.http_request = http_request

    def test_allowed_call_executes(self):
        """Allowed call should run the function body and return its result."""
        result = self.read_file(path="/tmp/data.csv")
        assert result == "content of /tmp/data.csv"

    def test_denied_call_raises_permission_error(self):
        """Denied call should raise PermissionError before execution."""
        with pytest.raises(PermissionError, match="skillruled denied"):
            self.read_file(path="/etc/passwd")

    def test_denied_http_raises(self):
        with pytest.raises(PermissionError, match="skillruled denied"):
            self.http_request(url="https://evil.com")

    def test_denied_write_raises(self):
        with pytest.raises(PermissionError, match="skillruled denied"):
            self.write_file(path="/tmp/out.txt")

    def test_permission_error_includes_source_text(self):
        """PermissionError message should include provenance from SKILL.md."""
        with pytest.raises(PermissionError, match="Only read files under /tmp"):
            self.read_file(path="/etc/passwd")

    def test_function_name_preserved(self):
        """functools.wraps should preserve the original function name."""
        assert self.read_file.__name__ == "read_file"
        assert self.write_file.__name__ == "write_file"
        assert self.http_request.__name__ == "http_request"

    def test_policy_attached_to_wrapper(self):
        """The wrapped function should have _skillruled_policy attribute."""
        assert hasattr(self.read_file, "_skillruled_policy")
        assert hasattr(self.read_file, "_skillruled_tool_name")
        assert self.read_file._skillruled_tool_name == "read_file"

    def test_construct_with_policy_object(self):
        """SkillGuardedTool should accept a Policy object directly."""
        policy = load_policy(CACHE_PATH)
        guarded = SkillGuardedTool(policy=policy)

        @guarded
        def read_file(path: str) -> str:
            return "ok"

        assert read_file(path="/tmp/test") == "ok"
        with pytest.raises(PermissionError):
            read_file(path="/etc/passwd")

    def test_construct_without_args_raises(self):
        with pytest.raises(ValueError, match="Must provide"):
            SkillGuardedTool()

    def test_unknown_tool_denied(self):
        """Tools not in the policy should be denied (default deny)."""
        guarded = SkillGuardedTool(policy_cache=CACHE_PATH)

        @guarded
        def unknown_tool(data: str) -> str:
            return "should not reach"

        with pytest.raises(PermissionError, match="default deny"):
            unknown_tool(data="test")
