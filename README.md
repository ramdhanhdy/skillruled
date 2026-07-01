# skillruled

skillruled is a runtime enforcement library for agent skill specifications. It parses
SKILL.md-style files containing natural-language permission boundaries, uses an LLM
to compile those boundaries into structured policy rules with evaluable Python
predicate expressions, and gates tool calls at runtime using a first-match-wins,
default-deny enforcement engine. Compiled policies can be cached to JSON for
offline enforcement with no LLM in the decision path.

> **Inspired by** the VIGIL paper: "Vigil: Runtime Enforcement of Behavioral
> Specifications in AI Agent Skills" (arXiv:2606.26524). skillruled is an
> independent prototype that explores a minimal Python implementation of
> that concept with JSON policy caching and AST-validated predicates.

## How it works

```
SKILL.md (NL boundaries)
       │
       ▼
  compile_policy()  ── LLM (LongCat-2.0) ──►  Policy (structured rules)
       │                                           │
       ▼                                           ▼
  save_policy() ──► policy.json ──► load_policy()
                                          │
                                          ▼
                                    enforce(tool_call, policy)
                                          │
                                     ALLOW / DENY
                              (no LLM call at decision time)
```

## Quick start

```bash
git clone https://github.com/ramdhanhdy/skillruled.git
cd skillruled
pip install -e .
```

### Compile a skill (requires LLM API key)

```python
from skillruled import parse_skill, compile_policy, enforce, save_policy

skill = parse_skill("skills/my-skill.md")
policy = compile_policy(skill.boundaries, api_key="...")
save_policy(policy, "policy.json")

result = enforce({"tool": "read_file", "args": {"path": "/etc/passwd"}}, policy)
print(result.verdict)  # "deny"
```

### Enforce from cache (no LLM, no API key)

```python
from skillruled import load_policy, enforce

policy = load_policy("policy.json")
result = enforce({"tool": "read_file", "args": {"path": "/tmp/data.csv"}}, policy)
print(result.verdict)  # "allow"
```

### Run the cached demo

```bash
python demo_cached.py
```

This runs without any API key — it loads the pre-built `policy_cache.json`.

## SKILL.md format

```markdown
---
name: csv-analyzer
allowed_tools: read_file
---

## Boundaries

1. Only read files under /tmp/.
2. Never make HTTP requests.
3. Never write files.
```

The natural-language boundaries are compiled into predicate rules like:

| Tool | Verdict | Condition | Predicate |
|---|---|---|---|
| read_file | allow | path under /tmp/ | `args.get('path', '').startswith('/tmp/')` |
| read_file | deny | path not under /tmp/ | `True` |
| http_request | deny | any HTTP request | `True` |
| write_file | deny | any write | `True` |

## AST-validated predicates

Predicates are validated through a restricted Python AST evaluator that:

- **Whitelists**: method calls (`.startswith()`, `.endswith()`, `.get()`),
  comparisons (`==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `not in`),
  boolean operators (`and`, `or`, `not`), and constants
- **Blocks**: dangerous names (`__import__`, `open`, `exec`, `eval`),
  dunder attributes, and mutating methods (`clear`, `pop`, `update`)
- **Enforces immutability**: `args` is passed as a `MappingProxyType` so
  mutation raises `TypeError` at runtime

**Limitations**: The current evaluator supports method-call predicates,
comparisons, and boolean logic. It is not a complete security sandbox --
do not use in adversarial scenarios where the agent may bypass the
enforcement layer. Library-level enforcement can be bypassed if tool
calls do not route through it.

## Positioning

Among reviewed open-source tools, skillruled explores compiling SKILL.md
NL boundaries into cached predicates -- a niche also described in the
VIGIL paper, though no shipped implementation from that work was found.

| Tool | NL→policy | Skill-spec native | JSON caching | Deterministic | Embeddable |
|---|:---:|:---:|:---:|:---:|:---:|
| **skillruled** | yes | yes | yes | yes | yes |
| SkillGuard | no | yes | no | hybrid | partial |
| IronCurtain | yes | no | no | yes | no |
| MCP Visor | no | no | no | yes | no |
| Mirage | no | no | no | yes | no |
| Lilith | yes | no | partial | n/a | no |
| PCAS | no | no | no | yes | no |

## Project structure

```
skillruled.py          # Core library: parse, compile, enforce, CLI, adapter
demo.py                # Live demo (requires LONGCAT_API_KEY)
demo_cached.py         # Cached demo (no API key needed)
example_skill.md       # Example SKILL.md spec
policy_cache.json      # Pre-built policy for cached demo
tests/
  test_evaluator.py          # 36 tests: AST operators, mutations, injection
  test_cached_workflow.py    # 8 tests: cache loading, enforcement, roundtrip
  test_cli_provenance_diff.py # 10 tests: CLI, provenance, diff
  test_adapter.py            # 10 tests: SkillGuardedTool decorator
pyproject.toml         # Packaging (not yet on PyPI)
```

## Testing

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
