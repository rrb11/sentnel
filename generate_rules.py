#!/usr/bin/env python3
"""
Sentnel Rule Generator — generate or update rules.yaml from a JSON/YAML input file.

Usage:
  python3 generate_rules.py <input_file> [--merge|--override] [--output PATH] [--dry-run] [--validate]

See example_input.yaml for a full template showing all supported rule types.
"""

import argparse
import datetime
import json
import os
import pathlib
import re
import sys

import yaml

VALID_ACTIONS = {"deny", "allow"}
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(SCRIPT_DIR, "rules.yaml")


class ValidationError(Exception):
    pass


# ── Parsing ───────────────────────────────────────────────────────────────────

def detect_format(path: str) -> str:
    ext = pathlib.Path(path).suffix.lower()
    if ext == ".json":
        return "json"
    if ext in (".yaml", ".yml"):
        return "yaml"
    raise ValueError(f"Cannot detect format from extension '{ext}'. Use .json, .yaml, or .yml")


def load_input(path: str) -> object:
    fmt = detect_format(path)
    with open(path, "r", encoding="utf-8") as f:
        if fmt == "json":
            return json.load(f)
        return yaml.safe_load(f)


# ── Validation ────────────────────────────────────────────────────────────────

def validate_single_rule(rule: object, index: int) -> list:
    if not isinstance(rule, dict):
        return [f"rule at index {index} must be a mapping/object, got {type(rule).__name__}"]

    errors = []
    rule_label = f"Rule at index {index}" + (f" (id: '{rule['id']}')" if "id" in rule else "")

    # id
    if "id" not in rule:
        errors.append("missing required field 'id'")
    else:
        rid = rule["id"]
        if not isinstance(rid, str) or not rid.strip():
            errors.append("'id' must be a non-empty string")
        elif not re.match(r'^[a-zA-Z0-9_\-]+$', rid):
            errors.append(f"'id' may only contain letters, digits, underscores, hyphens (got '{rid}')")
        elif rid.startswith("static_"):
            errors.append(f"'id' must not start with 'static_' — that prefix is reserved for hardcoded rules")

    # action
    if "action" not in rule:
        errors.append("missing required field 'action'")
    elif rule["action"] not in VALID_ACTIONS:
        errors.append(f"'action' must be 'deny' or 'allow' (got '{rule['action']}')")

    # match
    if "match" not in rule:
        errors.append("missing required field 'match'")
    else:
        match = rule["match"]
        if not isinstance(match, dict):
            errors.append("'match' must be a mapping/object")
        else:
            if "tool" not in match:
                errors.append("'match.tool' is required")
            elif not isinstance(match["tool"], str) or not match["tool"].strip():
                errors.append("'match.tool' must be a non-empty string")

            has_patterns_any = "patterns_any" in match
            has_pattern = "pattern" in match
            has_path = "path" in match
            match_field_count = sum([has_patterns_any, has_pattern, has_path])

            if match_field_count == 0:
                errors.append("'match' must include one of: 'patterns_any', 'pattern', or 'path'")
            elif match_field_count > 1:
                errors.append("'match' may include only one of 'patterns_any', 'pattern', or 'path'")
            else:
                if has_patterns_any:
                    pa = match["patterns_any"]
                    if not isinstance(pa, list) or len(pa) == 0:
                        errors.append("'match.patterns_any' must be a non-empty list")
                    else:
                        for i, p in enumerate(pa):
                            if not isinstance(p, str) or not p.strip():
                                errors.append(f"'match.patterns_any[{i}]' must be a non-empty string")

                if has_pattern:
                    p = match["pattern"]
                    if not isinstance(p, str) or not p.strip():
                        errors.append("'match.pattern' must be a non-empty string")

                if has_path:
                    ph = match["path"]
                    if not isinstance(ph, list) or len(ph) == 0:
                        errors.append("'match.path' must be a non-empty list")
                    else:
                        for i, p in enumerate(ph):
                            if not isinstance(p, str) or not p.strip():
                                errors.append(f"'match.path[{i}]' must be a non-empty string")

            # Soft warnings for semantic mismatches
            tool = match.get("tool", "")
            if has_path and tool == "Bash":
                print(f"WARNING: {rule_label}: 'path' match with tool 'Bash' will never fire (Bash uses 'patterns_any'/'pattern')", file=sys.stderr)
            if (has_patterns_any or has_pattern) and tool in ("Read", "Write", "Edit"):
                print(f"WARNING: {rule_label}: 'patterns_any'/'pattern' with tool '{tool}' will never fire (use 'path' instead)", file=sys.stderr)

    return [f"{rule_label}: {e}" for e in errors]


def validate_rules(data: object) -> list:
    """Validate parsed input. Returns list of rule dicts. Raises ValidationError on any error."""
    if not isinstance(data, dict):
        raise ValidationError("Input must be a YAML/JSON object with a 'rules' key at the top level")
    if "rules" not in data:
        raise ValidationError("Input must have a top-level 'rules' key")
    rules = data["rules"]
    if not isinstance(rules, list):
        raise ValidationError("'rules' must be a list")
    if len(rules) == 0:
        raise ValidationError("'rules' list must not be empty")

    all_errors = []
    seen_ids = {}
    for i, rule in enumerate(rules):
        errs = validate_single_rule(rule, i)
        all_errors.extend(errs)
        if isinstance(rule, dict) and "id" in rule and isinstance(rule["id"], str):
            rid = rule["id"]
            if rid in seen_ids:
                all_errors.append(f"Rule at index {i}: duplicate id '{rid}' (first seen at index {seen_ids[rid]})")
            else:
                seen_ids[rid] = i

    if all_errors:
        msg = "\n".join(f"  - {e}" for e in all_errors)
        raise ValidationError(f"Validation failed: {len(all_errors)} error(s):\n{msg}")

    return rules


# ── Merge / Override ──────────────────────────────────────────────────────────

def load_existing_rules(output_path: str) -> list:
    if not os.path.exists(output_path):
        return []
    with open(output_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict) or "rules" not in data:
        return []
    return data["rules"] if isinstance(data["rules"], list) else []


def merge_rules(existing: list, incoming: list) -> list:
    existing_by_id = {r["id"]: (i, r) for i, r in enumerate(existing) if isinstance(r, dict) and "id" in r}
    merged = list(existing)

    updated, added = [], []
    for rule in incoming:
        rid = rule["id"]
        if rid in existing_by_id:
            idx, _ = existing_by_id[rid]
            merged[idx] = rule
            updated.append(rid)
        else:
            merged.append(rule)
            added.append(rid)

    kept = [r["id"] for i, r in enumerate(existing) if isinstance(r, dict) and "id" in r
            and r["id"] not in {r2["id"] for r2 in incoming}]

    print(f"Merge summary:", file=sys.stderr)
    print(f"  Updated : {len(updated)} rule(s){(' ' + str(updated)) if updated else ''}", file=sys.stderr)
    print(f"  Added   : {len(added)} rule(s){(' ' + str(added)) if added else ''}", file=sys.stderr)
    print(f"  Kept    : {len(kept)} rule(s) (unchanged)", file=sys.stderr)
    print(f"  Total   : {len(merged)} rule(s)", file=sys.stderr)

    return merged


def override_rules(incoming: list) -> list:
    return incoming


# ── Serialization ─────────────────────────────────────────────────────────────

def ordered_rule(rule: dict) -> dict:
    match = rule["match"]
    ordered_match = {"tool": match["tool"]}
    for k in ("patterns_any", "pattern", "path"):
        if k in match:
            ordered_match[k] = match[k]
    return {"id": rule["id"], "match": ordered_match, "action": rule["action"]}


class _IndentedDumper(yaml.Dumper):
    """Dumper that indents list items relative to their parent key."""
    def increase_indent(self, flow=False, indentless=False):  # noqa: ARG002
        return super().increase_indent(flow, False)


def render_yaml(rules: list) -> str:
    timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    header = f"""\
# rules.yaml — Sentnel configurable rules
# Generated by generate_rules.py on {timestamp}
#
# Edit this file directly or regenerate with:
#   python3 generate_rules.py your_input.yaml --merge
#
# Schema:
#   id                  unique rule identifier (letters, digits, underscores, hyphens)
#   match.tool          Bash | Read | Write | Edit | MultiEdit | ...
#   match.patterns_any  OR list of substrings matched against Bash command (case-insensitive)
#   match.pattern       single substring matched against Bash command
#   match.path          list of substrings matched against file path (Read/Write/Edit)
#   action              deny | allow
#
# NOTE: Hardcoded static rules in hook.py always run before these and cannot be changed here.
"""
    ordered = [ordered_rule(r) for r in rules]
    body = yaml.dump(
        {"rules": ordered},
        Dumper=_IndentedDumper,
        default_flow_style=False,
        sort_keys=False,
        indent=2,
        allow_unicode=True,
    )

    # Insert blank line between rule entries for readability
    body = body.replace("\n  - id:", "\n\n  - id:")

    return header + "\n" + body


def write_output(content: str, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)


# ── Entry Point ───────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="generate_rules",
        description="Generate or update Sentnel rules.yaml from a JSON or YAML input file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python3 generate_rules.py example_input.yaml
  python3 generate_rules.py my_rules.json --merge
  python3 generate_rules.py my_rules.yaml --override
  python3 generate_rules.py my_rules.yaml --dry-run
  python3 generate_rules.py my_rules.yaml --validate
        """,
    )
    parser.add_argument("input_file", help="Path to input JSON or YAML file")
    parser.add_argument("--output", "-o", default=None, metavar="PATH",
                        help=f"Output path (default: {DEFAULT_OUT})")

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--merge", action="store_true", default=False,
                            help="Add/update rules by ID; keep existing rules not in input (default)")
    mode_group.add_argument("--override", action="store_true", default=False,
                            help="Replace all rules in rules.yaml with those from input")

    parser.add_argument("--dry-run", action="store_true",
                        help="Print generated YAML to stdout without writing any file")
    parser.add_argument("--validate", action="store_true",
                        help="Validate input only; do not write output")

    args = parser.parse_args()

    # Resolve output path
    output_path = args.output or DEFAULT_OUT
    if not output_path.endswith((".yaml", ".yml")):
        print(f"ERROR: --output path must end in .yaml or .yml (got '{output_path}')", file=sys.stderr)
        return 1

    # Load and validate input
    try:
        data = load_input(args.input_file)
    except FileNotFoundError:
        print(f"ERROR: Input file not found: {args.input_file}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: Failed to parse input file: {e}", file=sys.stderr)
        return 1

    try:
        incoming = validate_rules(data)
    except ValidationError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    print(f"Validation passed: {len(incoming)} rule(s) OK.", file=sys.stderr)

    if args.validate:
        return 0

    # Determine merge vs override (default to merge)
    use_override = args.override
    if use_override:
        final_rules = override_rules(incoming)
    else:
        existing = load_existing_rules(output_path)
        final_rules = merge_rules(existing, incoming)

    content = render_yaml(final_rules)

    if args.dry_run:
        print(content)
        return 0

    write_output(content, output_path)
    print(f"Written: {output_path} ({len(final_rules)} rule(s))", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
