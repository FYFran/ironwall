# Ironwall Skill for Claude Code

Run a 7-step security audit directly from Claude Code.

## Install

```bash
# 1. Install ironwall CLI
go install github.com/FYFran/ironwall/cmd/ironwall@latest

# 2. Install required tools
go install github.com/zricethezav/gitleaks/v8@latest

# 3. (Optional) AI features
export DEEPSEEK_API_KEY="sk-..."

# 4. Add skill to Claude Code
# Copy skills/SKILL.md to ~/.claude/skills/
cp skills/SKILL.md ~/.claude/skills/ironwall.md
```

## Usage in Claude Code

```
/ironwall scan .                    # Full scan
/ironwall quick .                   # Quick scan (secrets only)
/ironwall scan . --ai               # With AI analysis
/ironwall scan . --format markdown  # Generate report
```

## Verifying

```bash
ironwall doctor
# Should show all tools ✅
```

## Uninstalling

```bash
rm ~/.claude/skills/ironwall.md
```
