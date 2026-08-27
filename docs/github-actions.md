# GitHub Pull Request and Actions Integration

DevFoundry includes built-in support for GitHub Actions to provide rich feedback on pull requests, including inline annotations and job summaries.

---

## Setup

### Basic Workflow Configuration
Create or update `.github/workflows/ci.yml` in your repository:

```yaml
name: CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  analyze:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install pnpm
        uses: pnpm/action-setup@v3
        with:
          version: 9

      - name: Install dependencies
        run: pnpm install --frozen-lockfile

      - name: Build workspace
        run: pnpm build

      - name: Run DevFoundry CI Policy Check
        run: node apps/cli/bin/foundry.js ci --github
```

---

## Integration Features

### 1. Workflow Annotations
When running with the `--github` option, DevFoundry translates security findings, vulnerabilities, and severity alerts into inline annotations that appear directly on the files tab of the Pull Request.

**Annotated Finding Types:**
- New critical/high severity findings.
- Dependency vulnerabilities.
- Secret/credential exposures.

### 2. GITHUB_STEP_SUMMARY Job Summary
DevFoundry writes a rich markdown report summarizing findings by category (Security, Dependencies), policy evaluation messages, and advisory statuses. This markdown summary appears directly on the run overview page of your GitHub action execution.

#### Job Summary Example:
```markdown
# DevFoundry

## Result
❌ FAILED

## Findings

| Category | New | Remaining | Resolved |
| :--- | :---: | :---: | :---: |
| Security | 1 | 2 | 0 |
| Dependencies | 0 | 3 | 1 |

## Policy
- NEW critical finding: `src/auth.ts:42` (github-token)
- Secret detected

## Advisories
- Provider: OSV
- Status: Checked
```

---

## Stable Exit Codes

The DevFoundry CLI utilizes structured exit codes to integrate with standard workflow engines:

| Constant | Exit Code | Description |
|---|---|---|
| `EXIT_CODES.SUCCESS` | `0` | Analysis passed all policy constraints. |
| `EXIT_CODES.POLICY_VIOLATION` | `1` | Policy rules failed, or regression was detected. |
| `EXIT_CODES.INVALID_CONFIG` | `2` | Configuration errors or invalid inputs. |
| `EXIT_CODES.ANALYSIS_ERROR` | `3` | Internal engine, scanner, or file IO failure. |

---

## Security & Privacy (Zero Cloud Uploads)

> [!IMPORTANT]
> **No Repository Content is Transmitted.**
> DevFoundry performs all file searches, diffing, and baseline comparisons completely local to your runner runner. When checking dependency vulnerabilities, only package name, version, and ecosystem are queried against the public OSV.dev database. Source code and secret values never leave the runner environment.

---

## Dependency & Advisory Behaviors

If the OSV database is unreachable or query is skipped via `--offline`:
- Affected dependency validations are marked as `uncertain` / `partial`.
- The build **does not fail** solely because of the network/database check failure unless an actual violation is detected.

---

## Baseline Behaviors

Commit `.devfoundry/baseline.json` to version control to whitelist existing issues. DevFoundry CI will only alert and fail on **new findings** introduced in the current commit or pull request.
