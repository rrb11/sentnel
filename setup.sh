#!/bin/bash
set -e

VERSION="1.0.1"
CLAUDE_CONFIG="$HOME/.claude/settings.json"
INSTALL_DIR="$HOME/.sentnel"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $1"; }
fail() { echo -e "${RED}✗${NC} $1"; exit 1; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }

# ── Step 0: Determine Repo Directory ──────────────────────
# If hook.py exists in current dir, use it (local sidecar mode)
if [ -f "hook.py" ] && [ -f "rules.yaml" ]; then
  REPO_DIR="$(pwd)"
  echo "  🛡  Sentnel v$VERSION — Local Sidecar Mode"
else
  # Otherwise, ensure ~/.sentnel exists and is a clone
  echo "  🛡  Sentnel v$VERSION — One-Liner Install"
  if [ ! -d "$INSTALL_DIR/.git" ]; then
    echo "  Cloning Sentnel to $INSTALL_DIR..."
    git clone https://github.com/rrb11/sentnel.git "$INSTALL_DIR" --quiet || fail "Clone failed"
  else
    echo "  Updating Sentnel in $INSTALL_DIR..."
    (cd "$INSTALL_DIR" && git pull --quiet)
  fi
  REPO_DIR="$INSTALL_DIR"
fi

HOOK_CMD="python3 $REPO_DIR/hook.py"

echo "  ─────────────────────────────────────"
echo "  Repo: $REPO_DIR"
echo ""

# ── Step 1: Verify required files exist ───────────────────
for FILE in hook.py rules.yaml; do
  [ -f "$REPO_DIR/$FILE" ] || fail "Missing $FILE in $REPO_DIR"
done
ok "Source files verified"

# ── Step 2: Python dependency ─────────────────────────────
pip3 install pyyaml --quiet --break-system-packages 2>/dev/null \
  || pip3 install pyyaml --quiet \
  || fail "pip3 install pyyaml failed — install Python 3 and pip first"
ok "Dependencies ready"

# ── Step 3: Init local audit DB + .gitignore ──────────────
touch "$REPO_DIR/audit.db"
if ! grep -q "^audit\.db$" "$REPO_DIR/.gitignore" 2>/dev/null; then
  echo "audit.db" >> "$REPO_DIR/.gitignore"
fi
ok "Audit DB: $REPO_DIR/audit.db"

# ── Step 4: Register hook in ~/.claude/settings.json ──────
mkdir -p "$HOME/.claude"

python3 << PYEOF
import json, os, sys

config_path  = os.path.expanduser("~/.claude/settings.json")
hook_command = "$HOOK_CMD"
hook_entry   = {"matcher": "", "hooks": [{"type": "command", "command": hook_command}]}

if os.path.exists(config_path):
    try:
        with open(config_path) as f:
            config = json.load(f)
    except json.JSONDecodeError:
        print("  ⚠ Corrupt settings.json — backing up")
        os.rename(config_path, config_path + ".bak")
        config = {}
else:
    config = {}

config.setdefault("hooks", {})
config["hooks"].setdefault("PreToolUse", [])

existing = [
    h.get("command", "")
    for e in config["hooks"]["PreToolUse"] if isinstance(e, dict)
    for h in e.get("hooks", [])
]

if hook_command in existing:
    print("  Already registered — skipping (idempotent)")
    sys.exit(0)

# Remove any stale sentnel hook.py entries pointing elsewhere
config["hooks"]["PreToolUse"] = [
    e for e in config["hooks"]["PreToolUse"]
    if not any(
        "hook.py" in h.get("command", "")
        for h in (e.get("hooks", []) if isinstance(e, dict) else [])
    )
]

config["hooks"]["PreToolUse"].append(hook_entry)

with open(config_path, "w") as f:
    json.dump(config, f, indent=2)

print(f"  Registered: {hook_command}")
PYEOF

ok "Hook registered in ~/.claude/settings.json"

# ── Step 5: Smoke test ────────────────────────────────────
TEST='{"tool_name":"Bash","tool_input":{"command":"rm -rf /test"}}'
echo "$TEST" | python3 "$REPO_DIR/hook.py" 2>/dev/null
EXIT_CODE=$?

if   [ $EXIT_CODE -eq 2 ]; then ok "Smoke test passed — rm -rf blocked"
elif [ $EXIT_CODE -eq 0 ]; then warn "Hook ran but did not block — check rules.yaml"
else fail "Hook exited $EXIT_CODE — check hook.py"
fi

# ── Step 6: Validate settings.json ───────────────────────
python3 -c "
import json, os, sys
with open(os.path.expanduser('~/.claude/settings.json')) as f:
    c = json.load(f)
hooks = c.get('hooks', {}).get('PreToolUse', [])
assert isinstance(hooks, list) and len(hooks) > 0, 'No PreToolUse hooks found'
print('  PreToolUse hooks:', len(hooks))
for e in hooks:
    for h in e.get('hooks', []):
        print('   ->', h.get('command'))
" || fail "settings.json invalid"
ok "settings.json validated"

# ── Done ──────────────────────────────────────────────────
echo ""
echo "  ✅ Sentnel sidecar active!"
echo ""
echo "  Hook  → $REPO_DIR/hook.py"
echo "  Rules → $REPO_DIR/rules.yaml"
echo "  Audit → $REPO_DIR/audit.db"
echo "  Config→ $CLAUDE_CONFIG"
echo ""
echo "  Edit rules.yaml to customise — changes apply on next Claude tool call."
echo "  Uninstall: bash $REPO_DIR/uninstall.sh"
echo ""
