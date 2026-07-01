#!/usr/bin/env python3
"""
Test suite for skillruled AST evaluator (safe_eval_predicate).

Tests:
  1. Comparison operators (Eq, NotEq, Lt, LtE, Gt, GtE, In, NotIn)
  2. Boolean operators (And, Or)
  3. Original method-call predicates still work
  4. Mutating methods are blocked
  5. Dangerous names are blocked
  6. Dunder attributes are blocked
  7. args immutability (MappingProxyType)
  8. Full enforce() integration
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(__file__))
from skillruled import safe_eval_predicate, enforce, Policy, Rule


# ── 1. Comparison Operators ────────────────────────────────────────

class TestComparisonOperators:
    def test_eq(self):
        assert safe_eval_predicate("args.get('x', 0) == 1", {"x": 1}, "t")
        assert not safe_eval_predicate("args.get('x', 0) == 1", {"x": 2}, "t")

    def test_neq(self):
        assert safe_eval_predicate("args.get('x', 0) != 0", {"x": 1}, "t")
        assert not safe_eval_predicate("args.get('x', 0) != 0", {"x": 0}, "t")

    def test_lt(self):
        assert safe_eval_predicate("args.get('x', 0) < 5", {"x": 3}, "t")
        assert not safe_eval_predicate("args.get('x', 0) < 5", {"x": 5}, "t")

    def test_lte(self):
        assert safe_eval_predicate("args.get('x', 0) <= 5", {"x": 5}, "t")
        assert not safe_eval_predicate("args.get('x', 0) <= 5", {"x": 6}, "t")

    def test_gt(self):
        assert safe_eval_predicate("args.get('x', 0) > 5", {"x": 6}, "t")
        assert not safe_eval_predicate("args.get('x', 0) > 5", {"x": 5}, "t")

    def test_gte(self):
        assert safe_eval_predicate("args.get('x', 0) >= 5", {"x": 5}, "t")
        assert not safe_eval_predicate("args.get('x', 0) >= 5", {"x": 4}, "t")

    def test_in(self):
        assert safe_eval_predicate("args.get('x', '') in ('a', 'b')", {"x": "a"}, "t")
        assert not safe_eval_predicate("args.get('x', '') in ('a', 'b')", {"x": "c"}, "t")

    def test_not_in(self):
        assert safe_eval_predicate("args.get('x', '') not in ('a', 'b')", {"x": "c"}, "t")
        assert not safe_eval_predicate("args.get('x', '') not in ('a', 'b')", {"x": "a"}, "t")

    def test_string_eq(self):
        assert safe_eval_predicate("args.get('path', '') == '/tmp/'", {"path": "/tmp/"}, "t")
        assert not safe_eval_predicate("args.get('path', '') == '/tmp/'", {"path": "/etc/"}, "t")


# ── 2. Boolean Operators ───────────────────────────────────────────

class TestBooleanOperators:
    def test_and(self):
        assert safe_eval_predicate("args.get('x', 0) == 1 and args.get('y', 0) == 2", {"x": 1, "y": 2}, "t")
        assert not safe_eval_predicate("args.get('x', 0) == 1 and args.get('y', 0) == 2", {"x": 1, "y": 3}, "t")

    def test_or(self):
        assert safe_eval_predicate("args.get('x', 0) == 1 or args.get('y', 0) == 2", {"x": 1, "y": 0}, "t")
        assert safe_eval_predicate("args.get('x', 0) == 1 or args.get('y', 0) == 2", {"x": 0, "y": 2}, "t")
        assert not safe_eval_predicate("args.get('x', 0) == 1 or args.get('y', 0) == 2", {"x": 0, "y": 0}, "t")

    def test_not_with_and(self):
        pred = "not args.get('path', '').startswith('/etc') and args.get('path', '').startswith('/tmp')"
        assert safe_eval_predicate(pred, {"path": "/tmp/file"}, "t")
        assert not safe_eval_predicate(pred, {"path": "/etc/passwd"}, "t")
        assert not safe_eval_predicate(pred, {"path": "/home/user"}, "t")


# ── 3. Original Method-Call Predicates ─────────────────────────────

class TestMethodCallPredicates:
    def test_startswith(self):
        assert safe_eval_predicate("args.get('path', '').startswith('/tmp/')", {"path": "/tmp/data"}, "t")
        assert not safe_eval_predicate("args.get('path', '').startswith('/tmp/')", {"path": "/etc/passwd"}, "t")

    def test_not_startswith(self):
        assert safe_eval_predicate("not args.get('path', '').startswith('/tmp/')", {"path": "/etc/passwd"}, "t")
        assert not safe_eval_predicate("not args.get('path', '').startswith('/tmp/')", {"path": "/tmp/data"}, "t")

    def test_always_true(self):
        assert safe_eval_predicate("True", {}, "t")

    def test_constant_false(self):
        assert not safe_eval_predicate("False", {}, "t")


# ── 4. Mutating Methods Blocked ────────────────────────────────────

class TestMutatingMethodsBlocked:
    @pytest.mark.parametrize("method", ["clear", "pop", "popitem", "update", "setdefault", "sort"])
    def test_mutating_method_blocked(self, method):
        with pytest.raises(ValueError, match="Blocked mutating method"):
            safe_eval_predicate(f"args.{method}()", {"x": 1}, "t")


# ── 5. Dangerous Names Blocked ─────────────────────────────────────

class TestDangerousNamesBlocked:
    def test_import_blocked(self):
        with pytest.raises(ValueError, match="Blocked name"):
            safe_eval_predicate("__import__('os').system('id')", {}, "t")

    def test_open_blocked(self):
        with pytest.raises(ValueError, match="Blocked name"):
            safe_eval_predicate("open('/etc/passwd').read()", {}, "t")

    def test_exec_blocked(self):
        with pytest.raises(ValueError, match="Blocked name"):
            safe_eval_predicate('exec("import os")', {}, "t")

    def test_eval_blocked(self):
        with pytest.raises(ValueError, match="Blocked name"):
            safe_eval_predicate('eval("1+1")', {}, "t")


# ── 6. Dunder Attributes Blocked ───────────────────────────────────

class TestDunderBlocked:
    def test_dunder_class_blocked(self):
        with pytest.raises(ValueError, match="Blocked dunder attribute"):
            safe_eval_predicate("args.__class__", {}, "t")

    def test_dunder_import_blocked(self):
        with pytest.raises(ValueError, match="Blocked dunder attribute"):
            safe_eval_predicate("args.__import__", {}, "t")


# ── 7. Args Immutability ───────────────────────────────────────────

class TestArgsImmutability:
    def test_args_not_mutated_after_enforce(self):
        """Verify that enforce() does not mutate the original args dict."""
        original_args = {"path": "/tmp/data.csv", "mode": "r"}
        original_copy = dict(original_args)

        policy = Policy(rules=[
            Rule(tool="read_file", verdict="allow", condition="ok", predicate="True"),
        ])
        enforce({"tool": "read_file", "args": original_args}, policy)
        assert original_args == original_copy


# ── 8. Full enforce() Integration ──────────────────────────────────

class TestEnforceIntegration:
    def setup_method(self):
        self.policy = Policy(rules=[
            Rule(tool="read_file", verdict="allow", condition="path under /tmp/",
                 predicate="args.get('path', '').startswith('/tmp/')"),
            Rule(tool="read_file", verdict="deny", condition="path not under /tmp/",
                 predicate="True"),
            Rule(tool="http_request", verdict="deny", condition="any HTTP", predicate="True"),
            Rule(tool="write_file", verdict="deny", condition="any write", predicate="True"),
        ])

    def test_allow_within_tmp(self):
        result = enforce({"tool": "read_file", "args": {"path": "/tmp/data.csv"}}, self.policy)
        assert result.verdict == "allow"

    def test_deny_outside_tmp(self):
        result = enforce({"tool": "read_file", "args": {"path": "/etc/passwd"}}, self.policy)
        assert result.verdict == "deny"

    def test_deny_http(self):
        result = enforce({"tool": "http_request", "args": {"url": "https://evil.com"}}, self.policy)
        assert result.verdict == "deny"

    def test_deny_write(self):
        result = enforce({"tool": "write_file", "args": {"path": "/tmp/out.txt"}}, self.policy)
        assert result.verdict == "deny"

    def test_default_deny_unknown_tool(self):
        result = enforce({"tool": "unknown_tool", "args": {}}, self.policy)
        assert result.verdict == "deny"

    def test_comparison_predicate_in_enforce(self):
        """Test that comparison predicates work inside enforce()."""
        policy = Policy(rules=[
            Rule(tool="check", verdict="allow", condition="count <= 10",
                 predicate="args.get('count', 0) <= 10"),
            Rule(tool="check", verdict="deny", condition="count > 10", predicate="True"),
        ])
        assert enforce({"tool": "check", "args": {"count": 5}}, policy).verdict == "allow"
        assert enforce({"tool": "check", "args": {"count": 15}}, policy).verdict == "deny"

    def test_boolean_and_in_enforce(self):
        """Test that boolean AND predicates work inside enforce()."""
        policy = Policy(rules=[
            Rule(tool="check", verdict="allow", condition="both conditions",
                 predicate="args.get('x', 0) == 1 and args.get('y', 0) == 2"),
            Rule(tool="check", verdict="deny", condition="default", predicate="True"),
        ])
        assert enforce({"tool": "check", "args": {"x": 1, "y": 2}}, policy).verdict == "allow"
        assert enforce({"tool": "check", "args": {"x": 1, "y": 3}}, policy).verdict == "deny"
