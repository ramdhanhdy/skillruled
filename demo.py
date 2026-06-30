#!/usr/bin/env python3
"""
Demo script for skillruled — Runtime Enforcement for Agent Skill Specifications.

Loads example_skill.md, compiles a policy via LongCat, runs 4 test tool calls
through enforce(), and exits 0 only if all verdicts match expectations.
"""

import os
import sys

from skillruled import parse_skill, compile_policy, enforce, save_policy


def main():
    # 1. Load and parse the skill spec
    skill = parse_skill("example_skill.md")
    print(f"Loaded skill: {skill.name}")
    print(f"Allowed tools: {skill.tools}")
    print(f"Boundaries:\n{skill.boundaries}\n")

    # 2. Get API key from environment
    api_key = os.environ.get("LONGCAT_API_KEY", "")
    if not api_key:
        print("ERROR: LONGCAT_API_KEY environment variable not set")
        sys.exit(1)

    # 3. Compile policy via LongCat
    print("Compiling policy via LongCat...")
    policy = compile_policy(skill.boundaries, api_key)
    print(f"Compiled {len(policy.rules)} rules:")
    for i, rule in enumerate(policy.rules):
        print(f"  [{i}] {rule.verdict.upper():5s} tool={rule.tool:15s} "
              f"cond={rule.condition}")
        print(f"        predicate: {rule.predicate}")
    print()

    # 3b. Save compiled policy to cache for offline enforcement
    save_policy(policy, "policy_cache.json")
    print("Policy cached to policy_cache.json\n")

    # 4. Test tool calls — (a) allow, (b)(c)(d) deny
    test_calls = [
        {"tool": "read_file",    "args": {"path": "/tmp/data.csv"},   "expect": "allow"},
        {"tool": "read_file",    "args": {"path": "/etc/passwd"},     "expect": "deny"},
        {"tool": "http_request", "args": {"url": "https://evil.com"}, "expect": "deny"},
        {"tool": "write_file",   "args": {"path": "/tmp/out.txt"},    "expect": "deny"},
    ]

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
        print("All verdicts match expectations.")
        sys.exit(0)
    else:
        print("MISMATCH: some verdicts did not match expectations!")
        sys.exit(1)


if __name__ == "__main__":
    main()
