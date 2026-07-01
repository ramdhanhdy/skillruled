"""
skillruled — Runtime Enforcement for Agent Skill Specifications.

Parses SKILL.md specs with NL boundaries, compiles them into policy rules
via an LLM (LongCat-2.0), and gates tool calls at runtime.
"""

import ast
import json
import urllib.request
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


@dataclass
class Policy:
    rules: list = field(default_factory=list)  # list[Rule]


@dataclass
class EnforcementResult:
    verdict: str   # "allow" or "deny"
    reason: str


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
  {"tool":"read_file","verdict":"allow","condition":"path under /tmp/","predicate":"args.get('path','').startswith('/tmp/')"},
  {"tool":"read_file","verdict":"deny","condition":"path not under /tmp/","predicate":"True"},
  {"tool":"http_request","verdict":"deny","condition":"any HTTP request","predicate":"True"},
  {"tool":"write_file","verdict":"deny","condition":"any write","predicate":"True"}
]
"""


def _rule_from_dict(r: dict) -> Rule:
    """Build a Rule from a dict, applying safe defaults."""
    return Rule(
        tool=r.get("tool", "*"),
        verdict=r.get("verdict", "deny"),
        condition=r.get("condition", ""),
        predicate=r.get("predicate", "False"),
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
