# BUGFIX v0.4.1

## 4 bugs found in 2026-07-09 testing
1. Terminal shows all 7 steps in quick mode → terminal.go hardcoded loop
2. Single file path shows . → filepath.Rel returns . for same file
3. quick command missing --format/-o flags
4. Test coverage 5-26%

Fix plan: 3 files, ~27 lines, 30 minutes.
See docs/BUGFIX_v0.4.1.md under ironwall repo.
