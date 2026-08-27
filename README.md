# DevFoundry

> Build software with confidence.

DevFoundry is an open-source developer platform for understanding, securing,
maintaining, testing, and shipping software.

Modern software development is fragmented across dozens of tools.

You write code in one place.
Manage dependencies in another.
Run security scanners somewhere else.
Read logs somewhere else.
Manage CI somewhere else.
Deploy somewhere else.

DevFoundry is being built to bring the most important parts of that workflow
into one developer-first system.

## Vision

Our goal is simple:

**Make software development dramatically less painful.**

DevFoundry is not another programming language.
It is not another frontend framework.
It is not another AI coding chatbot.

It is a developer layer that works with the technologies developers already use.

## What we're building

DevFoundry will progressively provide:

- Project health analysis
- Security checks
- Secret detection
- Dependency intelligence
- Configuration analysis
- Testing insights
- Codebase intelligence
- Documentation intelligence
- Infrastructure checks
- Automated fixes
- Developer workflows
- AI-assisted project understanding

## First product

The first release is intentionally small.

```bash
npx @vrtex/foundry scan
```

## Dependency Vulnerability Scanning

DevFoundry scans your project's dependencies against [OSV.dev](https://osv.dev) — the
Open Source Vulnerabilities database — with no API key required.

```bash
npx @vrtex/foundry doctor                # Fast summary diagnostic scan
npx @vrtex/foundry scan                  # Full scan (project + secrets + OSV advisories)
npx @vrtex/foundry scan --offline        # Skip network advisory check (air-gapped / fast CI)
npx @vrtex/foundry scan --dependencies   # Dependency inventory + OSV advisories only
npx @vrtex/foundry scan --json           # Machine-readable output (includes advisoryInfo)
```

Advisory status in the report distinguishes between:

- **`✓ Checked`** — OSV responded successfully; findings are accurate.
- **`✗ Unavailable`** — OSV was unreachable; vulnerability status is unknown (not zero).
- **`— Not checked`** — Advisory lookup skipped via `--offline`; not zero.

**Privacy**: Only package name, version, and ecosystem are sent to OSV. Source files, secrets,
and environment variables are never transmitted.

See [docs/dependencies.md](docs/dependencies.md) for full documentation.

## Codebase Baselines and Verification

DevFoundry enables you to snapshot your codebase health using baselines, and verify changes to ensure no regressions are introduced.

```bash
npx @vrtex/foundry baseline create  # Run scan and save codebase health baseline
npx @vrtex/foundry baseline show    # Display details of the saved baseline
npx @vrtex/foundry verify           # Compare current codebase status against the baseline
npx @vrtex/foundry baseline clear   # Remove the saved baseline
```

**Privacy & Security**: Baseline files (`.devfoundry/baseline.json`) contain only non-sensitive metadata (fingerprints, rules, files). Raw values and secrets are **never** stored.

See [docs/baseline.md](docs/baseline.md) for full documentation.

## CI/CD Policy Engine & GitHub Actions

DevFoundry includes a baseline-aware **CI Policy Engine** to enforce security and dependency rules on CI runners:

```bash
npx @vrtex/foundry ci           # Run analysis, compare against baseline, and evaluate CI policies
npx @vrtex/foundry ci --strict  # Include test/fixture folders in CI checks
npx @vrtex/foundry ci --json    # Machine-readable policy evaluation result (exits 1 on failure)
```

- **Regression blocking**: Whitelists existing baseline issues; fails builds only on *newly introduced* findings.
- **Privacy & Security**: Operates completely local to the runner. DevFoundry **never** uploads repository contents.

See [docs/ci.md](docs/ci.md) for full documentation.

## Development Repository Status

The DevFoundry repository intentionally contains test fixtures that exercise
secret and security detection.

These fixtures are excluded from normal scanning and are used by strict-mode
tests. Running `foundry scan --strict` against the repository may therefore
produce findings by design.

