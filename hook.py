import json, sys, yaml, time, sqlite3, os

RULES_FILE = os.path.join(os.path.dirname(__file__), "rules.yaml")
_SENTNEL_DIR = os.path.expanduser("~/.sentnel")
DB_FILE = os.path.join(_SENTNEL_DIR, "audit.db")
DEBUG = os.environ.get("SENTNEL_DEBUG") == "1"

STATIC_RULES = [
    # Deletion — all known methods
    {"id": "static_rm",          "match": {"tool": "Bash", "patterns_any": ["rm ", "rmdir"]},                                      "action": "deny"},
    {"id": "static_shutil",      "match": {"tool": "Bash", "patterns_any": ["shutil.rmtree", "shutil.rmdir"]},                     "action": "deny"},
    {"id": "static_os_remove",   "match": {"tool": "Bash", "patterns_any": ["os.remove", "os.unlink", "os.rmdir"]},               "action": "deny"},
    {"id": "static_find_delete", "match": {"tool": "Bash", "patterns_any": ["find . -delete", "find / -delete", "-exec rm"]},     "action": "deny"},
    {"id": "static_git_clean",   "match": {"tool": "Bash", "patterns_any": ["git clean"]},                                         "action": "deny"},
    # Secrets
    {"id": "static_env_read",    "match": {"tool": "Read", "path": [".env", "id_rsa", "id_ed25519", ".pem", ".aws/credentials", ".kube/config", ".gnupg"]}, "action": "deny"},
    # Network exfil
    {"id": "static_curl",        "match": {"tool": "Bash", "patterns_any": ["curl ", "wget "]},                                    "action": "deny"},
    {"id": "static_python_net",  "match": {"tool": "Bash", "patterns_any": ["requests.get", "requests.post", "urllib.request", "http.client", "socket.connect"]}, "action": "deny"},
    # Reverse shell indicators
    {"id": "static_revshell",    "match": {"tool": "Bash", "patterns_any": ["bash -i", "/dev/tcp/", "nc -e", "ncat -e"]},         "action": "deny"},
    # SQL destruction
    {"id": "static_sql_drop",    "match": {"tool": "Bash", "patterns_any": ["drop table", "drop database", "drop schema", "truncate table"]}, "action": "deny"},
    # MCP config tampering
    {"id": "static_mcp_config",  "match": {"tool": "Write", "path": [".mcp.json", ".cursor/mcp.json", ".claude/settings.json"]},  "action": "deny"},
]

def load_rules():
    with open(RULES_FILE, "r") as f:
        return yaml.safe_load(f)["rules"]

def log_event(event, decision, reason):
    os.makedirs(_SENTNEL_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS events (
        ts REAL, tool TEXT, decision TEXT, reason TEXT, raw TEXT
    )
    """)
    c.execute("INSERT INTO events VALUES (?, ?, ?, ?, ?)", (
        time.time(),
        event.get("tool_name", ""),
        decision,
        reason,
        json.dumps(event)
    ))
    conn.commit()
    conn.close()

def match_rule(rule, event):
    tool = event.get("tool_name", "")
    tool_input = event.get("tool_input") or {}
    cmd  = (tool_input.get("command") or "").lower()
    path = (tool_input.get("path") or "").lower()

    if "tool" in rule["match"] and rule["match"]["tool"] != tool:
        return False

    if "patterns_any" in rule["match"]:
        for p in rule["match"]["patterns_any"]:
            if p.lower() in cmd:
                return True

    if "pattern" in rule["match"] and rule["match"]["pattern"].lower() in cmd:
        return True

    if "path" in rule["match"]:
        for p in rule["match"]["path"]:
            if p.lower() in path:
                return True

    return False

def evaluate(event):
    # Static rules always run first — cannot be deleted or tampered with
    for rule in STATIC_RULES:
        if match_rule(rule, event):
            return rule["action"], rule["id"]
    # Then user-defined rules from rules.yaml
    try:
        rules = load_rules()
        for rule in rules:
            if match_rule(rule, event):
                return rule["action"], rule["id"]
    except Exception as e:
        print(f"Sentnel: rules.yaml load error: {e}", file=sys.stderr)
    return "allow", None

def main():
    if DEBUG:
        print("🛡 Sentnel hook triggered", file=sys.stderr)
    try:
        event = json.loads(sys.stdin.read())
    except Exception as e:
        print(f"Sentnel: parse error: {e}", file=sys.stderr)
        print(json.dumps({"decision": "block", "reason": "invalid_input"}))
        sys.exit(2)

    if DEBUG:
        print(f"Sentnel: tool={event.get('tool_name')} cmd={str(event.get('tool_input',''))[:60]}", file=sys.stderr)

    decision, reason = evaluate(event)
    log_event(event, decision, reason)

    if DEBUG:
        print(f"Sentnel: decision={decision} rule={reason}", file=sys.stderr)

    if decision == "deny":
        print(json.dumps({
            "decision": "block",
            "reason": f"Sentnel blocked this action — rule: {reason}"
        }))
        sys.exit(2)
    else:
        print(json.dumps({"decision": "allow"}))
        sys.exit(0)

if __name__ == "__main__":
    main()
