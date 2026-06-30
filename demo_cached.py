#!/usr/bin/env python3
"""
Demo script for vigil — Cached enforcement (no LLM call).

Loads policy_cache.json (produced by demo.py), runs the same 4 test tool
calls through enforce(), and exits 0 only if all verdicts match expectations.

This script does NOT import compile_policy and does NOT read LONGCAT_API_KEY.
It is purely cache-driven.
"""

import sys

from vigil import load_policy, enforce


def main():
    # 1. Load the cached policy from disk (no LLM call)
    try:
        policy = load_policy("policy_cache.json")
    except FileNotFoundError:
        print("ERROR: policy_cache.json not found. Run demo.py first to create it.")
        sys.exit(1)

    print(f"Loaded cached policy: {len(policy.rules)} rules")
    for i, rule in enumerate(policy.rules):
        print(f"  [{i}] {rule.verdict.upper():5s} tool={rule.tool:15s} "
              f"cond={rule.condition}")
        print(f"        predicate: {rule.predicate}")
    print()

    # 2. Same 4 test tool calls as demo.py
    test_calls = [
        {"tool": "read_file",    "args": {"path": "/tmp/data.csv"},   "expect": "allow"},
        {"tool": "read_file",    "args": {"path": "/etc/passwd"},     "expect": "deny"},
        {"tool": "http_request", "args": {"url": "https://evil.com"}, "expect": "deny"},
        {"tool": "write_file",   "args": {"path": "/tmp/out.txt"},    "expect": "deny"},
    ]

    # 3. Enforce each call against the cached policy
    all_passed = True
    for call in test_calls:
        result = enforce(call, policy)
        ok = result.verdict == call["expect"]
        status = "PASS" if ok else "FAIL"
        if not ok:
            all_passed = False
        print(f"[{status}] {call['tool']:15s} args={call['args']}")
        print(f"        verdict={result.verdict:5s} (expected {call['expect']})"
              f"  reason={result.reason}")

    print()
    if all_passed:
        print("All normal verdicts match expectations (cached policy).")
    else:
        print("MISMATCH: some normal verdicts did not match expectations!")
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Injection-safety tests — malicious policy with dangerous predicates.
    # The AST validator must block each predicate, causing default-deny.
    # -----------------------------------------------------------------------
    print()
    print("--- Injection Safety Tests ---")
    print()

    from vigil import Policy, Rule

    malicious_policy = Policy(rules=[
        Rule(tool="*", verdict="allow", condition="inject",
             predicate="__import__('os').system('echo hacked')"),
        Rule(tool="*", verdict="allow", condition="inject",
             predicate="open('/etc/passwd').read()"),
        Rule(tool="*", verdict="allow", condition="inject",
             predicate="exec(\"import os; os.system('id')\")"),
    ])

    injection_calls = [
        {"tool": "read_file",  "args": {"path": "/tmp/data.csv"},
         "desc": "__import__ predicate blocked"},
        {"tool": "read_file",  "args": {"path": "/tmp/data.csv"},
         "desc": "open() predicate blocked"},
        {"tool": "read_file",  "args": {"path": "/tmp/data.csv"},
         "desc": "exec() predicate blocked"},
    ]

    for call in injection_calls:
        result = enforce(call, malicious_policy)
        ok = result.verdict == "deny"
        status = "PASS" if ok else "FAIL"
        if not ok:
            all_passed = False
        print(f"[{status}] {call['desc']}")
        print(f"        verdict={result.verdict:5s}  reason={result.reason}")

    print()
    if all_passed:
        print("All injection tests passed — dangerous predicates blocked.")
        sys.exit(0)
    else:
        print("FAIL: some injection predicates were NOT blocked!")
        sys.exit(1)


if __name__ == "__main__":
    main()
