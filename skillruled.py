"""
skillruled — Runtime Enforcement for Agent Skill Specifications.

Parses SKILL.md specs with NL boundaries, compiles them into policy rules
via an LLM (LongCat-2.0), and gates tool calls at runtime.
"""

import ast
import json
import urllib.request
import functools
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Data models (stdlib dataclasses — no pydantic)
# ---------------------------------------------------------------------------

@dataclass
class SkillSpec:
    name: str = ""
    tools: list = field(default_factory=list)
    boundaries: str = ""


@dataclass
class Rule:
    tool: str            # tool name, or "*" for all tools
    verdict: str         # "allow" or "deny"
    condition: str       # natural-language description
    predicate: str       # Python expression string
    source_text: str = ""  # NL boundary text this rule was compiled from (provenance)


@dataclass
class Policy:
    rules: list = field(default_factory=list)  # list[Rule]


@dataclass
class EnforcementResult:
    verdict: str   # "allow" or "deny"
    reason: str
    source_text: str = ""  # NL boundary text that caused this decision (provenance)


# ---------------------------------------------------------------------------
# parse_skill — read SKILL.md, extract frontmatter + boundaries
# ---------------------------------------------------------------------------

def parse_skill(path: str) -> SkillSpec:
    """Parse a SKILL.md file with simple YAML-like frontmatter."""
    with open(path, "r") as f:
        content = f.read()

    parts = content.split("---")
    if len(parts) >= 3:
        frontmatter_text = parts[1].strip()
        body_text = "---".join(parts[2:]).strip()
    else:
        frontmatter_text = ""
        body_text = content.strip()

    spec = SkillSpec()
    spec.boundaries = body_text

    for line in frontmatter_text.split("\n"):
        line = line.strip()
        if ":" in line:
            key, value = line.split(":", 1)
            key, value = key.strip(), value.strip()
            if key in ("name",):
                spec.name = value
            elif key in ("tools", "allowed_tools"):
                spec.tools = [t.strip() for t in value.split(",") if t.strip()]

    return spec


# ---------------------------------------------------------------------------
# compile_policy — send boundaries to LongCat, get structured rules back
# ---------------------------------------------------------------------------

_LONGCAT_URL = "https://api.longcat.chat/openai/v1/chat/completions"
_LONGCAT_MODEL = "LongCat-2.0"

_SYSTEM_PROMPT = """\
You are a policy compiler. Read the skill boundaries below and produce a JSON \
array of rule objects.

Each rule MUST have exactly these fields:
- "tool": the tool name this rule applies to, or "*" for all tools
- "verdict": "allow" or "deny"
- "condition": a short natural-language description of when the rule applies
- "predicate": a Python expression that evaluates to True when the rule applies
- "source_text": the exact natural-language boundary sentence from the skill spec that this rule was derived from (verbatim quote)

The predicate is evaluated with access to:
- "args": a dict of the tool call's arguments (e.g. args.get('path',''))
- "tool": the tool name string

Predicate examples:
- "args.get('path','').startswith('/tmp/')"        # path is under /tmp/
- "not args.get('path','').startswith('/tmp/')"      # path is NOT under /tmp/
- "True"                                             # always matches

Rules for ordering:
1. More specific rules come first (first match wins, like a firewall).
2. For a boundary like "only read files under /tmp/", create TWO rules:
   an allow rule with predicate "args.get('path','').startswith('/tmp/')" 
   followed by a deny rule with predicate "True".
3. For a boundary like "never make HTTP requests", create ONE deny rule 
   for the relevant tool with predicate "True".

Output ONLY the JSON array. No markdown, no explanation.

Example output:
[
  {"tool":"read_file","verdict":"allow","condition":"path under /tmp/","predicate":"args.get('path','').startswith('/tmp/')","source_text":"Only read files under /tmp/."},
  {"tool":"read_file","verdict":"deny","condition":"path not under /tmp/","predicate":"True","source_text":"Only read files under /tmp/."},
  {"tool":"http_request","verdict":"deny","condition":"any HTTP request","predicate":"True","source_text":"Never make HTTP requests."},
  {"tool":"write_file","verdict":"deny","condition":"any write","predicate":"True","source_text":"Never write files."}
]
"""


def _rule_from_dict(r: dict) -> Rule:
    """Build a Rule from a dict, applying safe defaults."""
    return Rule(
        tool=r.get("tool", "*"),
        verdict=r.get("verdict", "deny"),
        condition=r.get("condition", ""),
        predicate=r.get("predicate", "False"),
        source_text=r.get("source_text", ""),
    )


def compile_policy(boundaries: str, api_key: str) -> Policy:
    """Compile NL boundaries into structured policy rules via LongCat."""
    body = json.dumps({
        "model": _LONGCAT_MODEL,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": f"Skill boundaries:\n\n{boundaries}"},
        ],
        "temperature": 0,
    }).encode("utf-8")

    req = urllib.request.Request(
        _LONGCAT_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    with urllib.request.urlopen(req) as resp:
        resp_data = json.loads(resp.read().decode("utf-8"))

    content = resp_data["choices"][0]["message"]["content"]

    # Extract JSON array — handle markdown fences or extra text
    start = content.find("[")
    end = content.rfind("]")
    if start == -1 or end == -1:
        raise ValueError(f"No JSON array found in LLM response:\n{content}")
    rules_json = content[start:end + 1]

    raw_rules = json.loads(rules_json)
    rules = [_rule_from_dict(r) for r in raw_rules]
    return Policy(rules=rules)


# ---------------------------------------------------------------------------
# safe_eval_predicate — AST-validated predicate evaluation (no raw eval)
# ---------------------------------------------------------------------------

_ALLOWED_NODES = frozenset({
    ast.Expression, ast.BoolOp, ast.UnaryOp, ast.Compare, ast.Call,
    ast.Attribute, ast.Constant, ast.Name, ast.Tuple, ast.List, ast.keyword,
    ast.Load,
    # Comparison operators (sub-nodes of ast.Compare)
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn,
    # Boolean operators (sub-nodes of ast.BoolOp)
    ast.And, ast.Or,
    # Unary not operator (sub-node of ast.UnaryOp)
    ast.Not,
})
_ALLOWED_NAMES = frozenset({"args", "tool", "True", "False", "None"})

# Methods that mutate the args dict — blocked to keep enforcement side-effect-free
_MUTATING_METHODS = frozenset({
    "clear", "pop", "popitem", "update", "setdefault", "__setitem__",
    "remove", "discard", "sort", "reverse", "append", "extend", "insert",
})

# Dangerous builtins/names blocked even if they appear in the namespace
_BLOCKED_NAMES = frozenset({
    "__import__", "open", "exec", "eval", "compile", "globals", "locals",
    "getattr", "setattr", "delattr", "hasattr", "vars", "dir", "type",
    "object", "input", "breakpoint", "exit", "quit",
})


def safe_eval_predicate(predicate: str, args: dict, tool: str) -> bool:
    """Validate a predicate via AST, then eval it in a restricted namespace.

    Raises ValueError if any disallowed node type, dunder attribute,
    non-whitelisted name, or mutating method is found.
    Returns the boolean result of the evaluated expression.
    """
    import types

    tree = ast.parse(predicate, mode="eval")
    for node in ast.walk(tree):
        if type(node) not in _ALLOWED_NODES:
            raise ValueError(f"Disallowed node type: {type(node).__name__}")
        if isinstance(node, ast.Attribute):
            if "__" in node.attr:
                raise ValueError(f"Blocked dunder attribute: {node.attr}")
            if node.attr in _MUTATING_METHODS:
                raise ValueError(f"Blocked mutating method: {node.attr}")
        if isinstance(node, ast.Name) and node.id not in _ALLOWED_NAMES:
            raise ValueError(f"Blocked name: {node.id}")
        if isinstance(node, ast.UnaryOp) and not isinstance(node.op, ast.Not):
            raise ValueError(f"Blocked unary operator: {type(node.op).__name__}")
    code = compile(tree, "<predicate>", "eval")
    # Pass args as an immutable MappingProxyType so mutation raises TypeError
    safe_args = types.MappingProxyType(dict(args)) if isinstance(args, dict) else args
    return bool(eval(code, {"__builtins__": {}}, {"args": safe_args, "tool": tool}))


# ---------------------------------------------------------------------------
# enforce — check a tool call against the compiled policy
# ---------------------------------------------------------------------------

def enforce(tool_call: dict, policy: Policy) -> EnforcementResult:
    """
    Check a tool call against the policy.
    First matching rule wins. Default deny if no rule matches.
    """
    tool = tool_call.get("tool", "")
    args = tool_call.get("args", {})

    for rule in policy.rules:
        # Does this rule apply to this tool?
        if rule.tool != "*" and rule.tool != tool:
            continue

        # Evaluate the predicate via the safe AST-validated evaluator
        try:
            matches = safe_eval_predicate(rule.predicate, args, tool)
        except Exception:
            continue

        if matches:
            return EnforcementResult(
                verdict=rule.verdict,
                reason=rule.condition,
                source_text=rule.source_text,
            )

    return EnforcementResult(verdict="deny", reason="No matching rule (default deny)")


# ---------------------------------------------------------------------------
# save_policy / load_policy — persist a compiled Policy to JSON and reload it
# ---------------------------------------------------------------------------

def save_policy(policy: Policy, path: str) -> None:
    """Serialize a Policy (list of Rule dataclasses) to a JSON file."""
    data = {
        "rules": [
            {
                "tool": rule.tool,
                "verdict": rule.verdict,
                "condition": rule.condition,
                "predicate": rule.predicate,
                "source_text": rule.source_text,
            }
            for rule in policy.rules
        ]
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def load_policy(path: str) -> Policy:
    """Read a JSON file produced by save_policy and reconstruct a Policy."""
    with open(path, "r") as f:
        data = json.load(f)
    rules = [_rule_from_dict(r) for r in data.get("rules", [])]
    return Policy(rules=rules)


# ---------------------------------------------------------------------------
# diff_policy — show what predicates were auto-derived (B3)
# ---------------------------------------------------------------------------

def diff_policy(policy: Policy) -> str:
    """Produce a human-readable diff of compiled rules with source provenance.

    For each rule, shows the verdict, tool, predicate, and the NL boundary
    text it was derived from. This is the transparency layer that makes
    LLM-compiled policies auditable.
    """
    if not policy.rules:
        return "No rules compiled."

    lines = [f"{len(policy.rules)} rules compiled:\n"]
    for i, rule in enumerate(policy.rules, 1):
        lines.append(f"  {i}. {rule.verdict.upper():5s} {rule.tool:15s}")
        lines.append(f"     predicate: {rule.predicate}")
        if rule.source_text:
            lines.append(f'     from: "{rule.source_text}"')
        else:
            lines.append("     from: (no source text recorded)")
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI — skillruled compile / enforce / diff (B1 + B3)
# ---------------------------------------------------------------------------

def cli():
    """Command-line interface for skillruled.

    Usage:
      skillruled compile <skill.md> [--output policy.json] [--show]
      skillruled enforce --policy policy.json --tool <name> [--args '{"k":"v"}']
      skillruled diff <policy.json>
    """
    import sys

    if len(sys.argv) < 2:
        print("usage: skillruled <compile|enforce|diff> [options]")
        sys.exit(1)

    command = sys.argv[1]

    if command == "compile":
        _cli_compile(sys.argv[2:])

    elif command == "enforce":
        _cli_enforce(sys.argv[2:])

    elif command == "diff":
        _cli_diff(sys.argv[2:])

    else:
        print(f"Unknown command: {command}")
        print("usage: skillruled <compile|enforce|diff> [options]")
        sys.exit(1)


def _cli_compile(args: list):
    """skillruled compile <skill.md> [--output policy.json] [--show]"""
    import sys
    import os

    if not args:
        print("usage: skillruled compile <skill.md> [--output policy.json] [--show]")
        sys.exit(1)

    skill_path = args[0]
    output_path = "policy.json"
    show = False

    i = 1
    while i < len(args):
        if args[i] == "--output" and i + 1 < len(args):
            output_path = args[i + 1]
            i += 2
        elif args[i] == "--show":
            show = True
            i += 1
        else:
            i += 1

    skill = parse_skill(skill_path)
    print(f"Loaded skill: {skill.name}")
    print(f"Boundaries: {skill.boundaries[:200]}...")

    api_key = os.environ.get("LONGCAT_API_KEY", "")
    if not api_key:
        print("ERROR: LONGCAT_API_KEY environment variable not set")
        sys.exit(1)

    print("Compiling policy via LongCat...")
    policy = compile_policy(skill.boundaries, api_key)
    print(f"Compiled {len(policy.rules)} rules")

    save_policy(policy, output_path)
    print(f"Policy saved to {output_path}")

    if show:
        print()
        print(diff_policy(policy))


def _cli_enforce(args: list):
    """skillruled enforce --policy policy.json --tool <name> [--args '{"k":"v"}']"""
    import sys

    policy_path = None
    tool_name = None
    args_json = "{}"

    i = 0
    while i < len(args):
        if args[i] == "--policy" and i + 1 < len(args):
            policy_path = args[i + 1]
            i += 2
        elif args[i] == "--tool" and i + 1 < len(args):
            tool_name = args[i + 1]
            i += 2
        elif args[i] == "--args" and i + 1 < len(args):
            args_json = args[i + 1]
            i += 2
        else:
            i += 1

    if not policy_path or not tool_name:
        print("usage: skillruled enforce --policy policy.json --tool <name> [--args '{\"k\":\"v\"}']")
        sys.exit(1)

    policy = load_policy(policy_path)
    call_args = json.loads(args_json)
    result = enforce({"tool": tool_name, "args": call_args}, policy)

    print(json.dumps({
        "verdict": result.verdict,
        "reason": result.reason,
        "source_text": result.source_text,
    }, indent=2))

    if result.verdict == "deny":
        sys.exit(2)


def _cli_diff(args: list):
    """skillruled diff <policy.json>"""
    import sys

    if not args:
        print("usage: skillruled diff <policy.json>")
        sys.exit(1)

    policy = load_policy(args[0])
    print(diff_policy(policy))


# ---------------------------------------------------------------------------
# SkillGuardedTool — framework adapter decorator (B4)
# ---------------------------------------------------------------------------

class SkillGuardedTool:
    """Decorator that enforces a skill policy before a tool function runs.

    Wraps any Python function. The tool name is derived from the function
    name, and the call args are the function's keyword arguments.

    Args:
        policy_cache: Path to a compiled policy JSON file.
        policy: An already-loaded Policy object (alternative to policy_cache).

    Raises:
        PermissionError: When the policy denies the tool call.

    Example:
        guarded = SkillGuardedTool(policy_cache="policy.json")

        @guarded
        def read_file(path: str) -> str:
            return open(path).read()

        # If the policy denies the call, PermissionError is raised before
        # the function body executes.
    """

    def __init__(self, policy_cache: str = "", policy=None):
        if policy is not None:
            self._policy = policy
        elif policy_cache:
            self._policy = load_policy(policy_cache)
        else:
            raise ValueError("Must provide either policy_cache or policy")

    def __call__(self, func):
        tool_name = func.__name__
        policy = self._policy

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            tool_call = {"tool": tool_name, "args": dict(kwargs)}
            result = enforce(tool_call, policy)
            if result.verdict == "deny":
                source = f' (source: "{result.source_text}")' if result.source_text else ""
                raise PermissionError(
                    f"skillruled denied {tool_name}: {result.reason}{source}"
                )
            return func(*args, **kwargs)

        wrapper._skillruled_policy = policy
        wrapper._skillruled_tool_name = tool_name
        return wrapper
