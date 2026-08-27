# Codebase Baselines and Verification

DevFoundry includes a **baseline/snapshot engine** that allows tracking and verifying the security and dependency health of a codebase over time. This enables teams to prevent regressions and verify that previously detected issues have actually been resolved.

---

## The Workflow

```
       Initial Scan
            │
            ▼
 foundry baseline create
            │
            ▼
.devfoundry/baseline.json
            │
            ▼
   [Developer fixes code]
            │
            ▼
      foundry verify
            │
     ┌──────┴──────┐
     ▼             ▼
  ✓ PASSED      ✗ FAILED
```

---

## Baseline Storage: `.devfoundry/baseline.json`

Running `foundry baseline create` creates a `.devfoundry/` directory and writes `baseline.json`.

### Safety Guarantee: No Credential Leakage

The baseline file stores information about **what the codebase health looked like**, but **never stores actual credential values**.

Stored fields per finding:
- `fingerprint` (unique identity hash)
- `ruleId`
- `category`
- `severity`
- `file`
- `line`
- `metadata` (optional non-sensitive details)

Sensitive fields such as the raw finding `message` or `remediation` containing exposed tokens (e.g. `ghp_...3XYZ`) are **completely omitted**.

### Version Control Policy

DevFoundry **does not** automatically add `.devfoundry/` to `.gitignore`.
- **Individual use**: You can add `.devfoundry/` to your local `.gitignore` if you prefer to manage baselines locally.
- **Team/CI use**: You can commit `.devfoundry/baseline.json` to version control. This establishes a shared health baseline for the team and fails CI runs if any new issues (regressions) are introduced.

---

## CLI Reference

### `foundry baseline create`

Runs analysis and saves the codebase baseline to `.devfoundry/baseline.json`.

```bash
foundry baseline create
foundry baseline create --strict   # Include tests/fixtures in baseline
foundry baseline create --offline  # Save baseline without querying OSV
```

### `foundry baseline show`

Displays metadata and statistics about the currently saved baseline:

```
DEVFOUNDRY BASELINE

Created       2026-08-27
Tool version  0.1.6

Findings      4
  Security    3
  Dependencies 1

Advisories
  OSV
  ✓ Checked
```

### `foundry baseline clear`

Deletes the baseline file and cleans up the `.devfoundry` directory if empty:

```bash
foundry baseline clear
```

### `foundry verify`

Compares the current codebase findings against the saved baseline.

```bash
foundry verify
foundry verify --strict
foundry verify --offline
foundry verify --json
```

**Options:**
- `--previous <path>`: For backward compatibility, specifies an arbitrary JSON file containing a findings array or `AnalysisResult` instead of using the baseline file.

---

## Verification Status Semantics

Verification maps current findings to previous findings using stable fingerprints and computes one of three statuses:

| Status | Outcome | Meaning |
|---|---|---|
| **`✓ PASSED`** | Success | All previous findings resolved; no new findings introduced. |
| **`~ PARTIAL`** | Warning | Some findings resolved but some remain; OR dependency vulnerability status cannot be verified. |
| **`✗ FAILED`** | Failure | New findings were introduced; OR remaining findings exist with no progress made. |

### Handling Advisory Uncertainty

If the dependency advisory provider (OSV) is unavailable or skipped (offline mode), previous vulnerability findings cannot be confirmed as resolved. DevFoundry enforces the following safety rules:

- **Security findings resolved + advisories ok** → `PASSED`
- **Security findings resolved + advisories unavailable/offline** → `PARTIAL`
- **Dependency vulnerability cannot be verified** → `PARTIAL`, never `PASSED`

When verification returns `✗ FAILED` or `~ PARTIAL`, the CLI exits with code `1` to prevent false clean results in development and CI environments.
