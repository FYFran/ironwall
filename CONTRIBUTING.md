# Contributing to Ironwall

First off, thanks for being here. Ironwall is built by a CS freshman learning security — contributions at any level are welcome.

## Ways to Contribute

### 1. Add Gotchas (Easiest)

Found a security pattern that automated scanners miss? Add it to `docs/gotchas.md`.

**Format:**
```markdown
### X1: Short Title

```lang
// ❌ vulnerable code here
```

**Why missed:** One sentence explaining why scanners miss this.
**Ironwall detection:** Which step catches it.
```

Real examples make the best gotchas — just make sure to anonymize any proprietary code.

### 2. Add Test Data

Clone a real vulnerability pattern into `testdata/`. Good test data:
- Is minimal (10-30 lines)
- Demonstrates exactly ONE vulnerability
- Includes a comment explaining what's wrong
- Is clearly marked as test/example code (not production)

### 3. Fix a Bug or Add a Feature

1. Fork the repo
2. Create a branch: `git checkout -b fix/my-fix`
3. Run `go test ./...` to make sure everything passes
4. Make your change
5. Add tests if applicable
6. Run `go vet ./...` and `go test ./...`
7. Push and open a PR

## Development

```bash
# Clone
git clone https://github.com/FYFran/ironwall.git
cd ironwall

# Build
go build ./cmd/ironwall

# Run tests
go test ./... -v

# Run vet
go vet ./...

# Self-audit
go run ./cmd/ironwall scan .

# Check environment
go run ./cmd/ironwall doctor
```

## Architecture

```
cmd/ironwall/        CLI entry (cobra commands)
internal/
  pipeline/          Step interface + 7 step implementations
  scanner/           External tool wrappers (gitleaks, gosec, semgrep, deps)
  report/            Terminal / Markdown / JSON output
  classify/          Severity mapping + attack scenario verification
  ai/                DeepSeek API client + prompt templates
  config/            Configuration structs + defaults
docs/                Methodology, gotchas, examples
testdata/            Intentionally vulnerable test code
```

## Adding a New Audit Step

1. Create `internal/pipeline/stepX_name.go`
2. Implement the `Step` interface (`Name`, `Description`, `Run`, `IsSkippable`, `RequiredTools`)
3. Register in `cmd/ironwall/scan.go`
4. Add to `internal/config/defaults.go` (StepNames, StepEmoji)

## Code Style

- Standard Go formatting (`go fmt`)
- 100 character line limit (soft)
- Tests use [testify](https://github.com/stretchr/testify)
- Comments in English

## Questions?

Open an issue. I'm learning too — no question is too basic.
