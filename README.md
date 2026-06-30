# skillruled

skillruled is a runtime enforcement library for agent skill specifications. It reads
SKILL.md-style specs with natural-language boundaries, uses the LongCat-2.0 LLM
to compile those boundaries into structured policy rules with evaluable
predicates, and gates tool calls against the compiled policy at runtime
(first-match-wins, default-deny).

## Attribution

This project is an independent implementation inspired by the concepts described in:

> **VIGIL: Runtime Reference Monitors for Agent Skill Specifications**
> arXiv:2606.26524 (published 2026-06-25)

The VIGIL paper formalizes the idea of translating natural-language skill
boundaries into runtime reference monitors. This library is not affiliated with
or endorsed by the paper's authors. It is an independent, minimal implementation
of that concept.

## Setup

Set your LongCat API key:

    export LONGCAT_API_KEY=your-key-here

## Run

    python3 demo.py

The demo loads `example_skill.md`, compiles a policy via LongCat, and runs 4
test tool calls (1 allow, 3 deny). It exits 0 if all verdicts match expectations.

## Caching

After compiling a policy, `demo.py` saves it to `policy_cache.json` via
`save_policy()`. You can then enforce the cached policy without any LLM call
and without `LONGCAT_API_KEY`:

    python3 demo.py          # compiles via LongCat + saves policy_cache.json
    python3 demo_cached.py  # loads policy_cache.json + enforces (no LLM call)

The cache is a human-readable JSON file with a `"rules"` array. Each rule has
`tool`, `verdict`, `condition`, and `predicate` fields. This proves the LLM is
only needed at compile time, not at enforcement time.

## Security

Predicates are validated with `safe_eval_predicate()` before evaluation. This
function parses each predicate into an AST and rejects any expression that
contains:

- Disallowed node types (only Expression, BoolOp, UnaryOp(Not), Compare, Call,
  Attribute, Constant, Name, Tuple, List, keyword are permitted)
- Dunder attribute access (any attribute containing `__`, e.g. `__class__`,
  `__subclasses__`)
- Non-whitelisted names (only `args`, `tool`, `True`, `False`, `None` are
  allowed — `__import__`, `open`, `exec`, `getattr` are all blocked)
- Non-`Not` unary operators

Rejected predicates raise `ValueError`, which `enforce()` catches and treats
as a non-match, falling through to default-deny. Dangerous predicates like
`__import__('os').system(...)`, `open('/etc/passwd').read()`, and
`exec(...)` are therefore blocked before they can execute.
