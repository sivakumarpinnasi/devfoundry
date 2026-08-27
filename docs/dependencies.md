# Dependency Vulnerability Scanning

DevFoundry scans your project's dependencies against the [OSV.dev](https://osv.dev) public vulnerability database.

## What is OSV?

[OSV (Open Source Vulnerabilities)](https://osv.dev) is a vulnerability database and triage infrastructure for open source projects. It aggregates data from GitHub Security Advisories (GHSA), NVD, and other sources. OSV is free to query with no API key required.

---

## What DevFoundry sends to OSV

**Only the following information is transmitted per dependency:**

| Field | Example |
|---|---|
| `name` | `lodash` |
| `version` | `4.17.20` |
| `ecosystem` | `npm` |

**DevFoundry never sends:**
- Source code or file contents
- Secret values, tokens, or credentials
- Environment variables
- Repository metadata or commit history

Queries are batched into a single POST request to `https://api.osv.dev/v1/querybatch`. No data is stored or forwarded beyond OSV's own servers.

---

## Advisory availability states

After running `foundry doctor`, the **Advisories** section shows one of three states:

| Status | Meaning |
|---|---|
| `✓ Checked` | OSV was successfully queried. Findings reflect actual vulnerabilities. |
| `✗ Unavailable` | OSV could not be reached (network error, timeout, HTTP error). Vulnerability status is **unknown** — not zero. |
| `— Not checked` | Advisory lookup was intentionally skipped (e.g. `--offline`). Vulnerability status is **not checked** — not zero. |

> **Critical invariant**: DevFoundry never reports `0 vulnerabilities` when the advisory lookup failed or was skipped. The `Vulnerable` line in the report will always reflect the actual lookup status.

---

## Offline mode

Use `--offline` to skip all network advisory checks:

```bash
foundry doctor --offline
```

In offline mode:
- Dependency inventory (total, direct, transitive counts) is still computed from lockfiles
- No request is sent to OSV
- The `Vulnerable` line shows `Not checked`
- The score is not penalized for the missing advisory check

This is useful for:
- Air-gapped environments
- CI pipelines where network access is restricted
- Fast local scans that don't need vulnerability data

---

## How severity is mapped

OSV advisories include severity information from multiple sources. DevFoundry resolves severity in this priority order:

### 1. `database_specific.severity` (string label)

Most GitHub Security Advisories include a pre-computed string label:

| OSV label | DevFoundry severity |
|---|---|
| `CRITICAL` | `critical` |
| `HIGH` | `high` |
| `MODERATE` | `medium` |
| `LOW` | `low` |

### 2. `ecosystem_specific.severity` (string label)

Same mapping as above, used when `database_specific.severity` is absent.

### 3. CVSS v3/v4 vector heuristic

When only a CVSS vector string is available (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), DevFoundry applies this approximation based on the Confidentiality (C), Integrity (I), Availability (A), and Scope (S) metric values:

| Condition | DevFoundry severity |
|---|---|
| All three of C/I/A are High | `critical` |
| Scope:Changed + at least one High | `critical` |
| Two or more of C/I/A are High | `critical` |
| One of C/I/A is High | `high` |
| One of C/I/A is Medium | `medium` |
| All Low or None | `low` |

> This is an approximation, not an exact CVSS base score calculation. For exact scores, refer to the upstream advisory link.

### 4. Documented fallback

If severity cannot be determined from any source, DevFoundry uses `medium`. This is conservative (avoids false critical/high alerts) and is clearly documented.

---

## Scoring

Only **confirmed vulnerability findings** (status `ok`) affect the project score. A failed network request (`unavailable`) or skipped check (`not_checked`) does **not** reduce the score.

Penalty per severity level:

| Severity | Score penalty |
|---|---|
| `critical` | −40 |
| `high` | −20 |
| `medium` | −10 |
| `low` | −2 |

---

## Performance

For large projects with hundreds of dependencies:

1. **Deduplication**: Identical `name@version` pairs are queried only once.
2. **Batch API**: All unique packages are sent in a single POST request to `/v1/querybatch` (up to 1000 per request).
3. **In-memory cache**: Results are cached for the lifetime of the scan. Re-running analysis on the same package does not make additional HTTP requests.
4. **15-second timeout**: Each batch request times out after 15 seconds. On timeout, the advisory status is reported as `unavailable`.

---

## Limitations

- **Semver range matching** is performed server-side by OSV. DevFoundry sends the installed version; OSV determines whether it falls within a vulnerable range.
- **Transitive dependencies** are included in OSV queries. A vulnerability in a deep transitive dependency will be reported.
- **Outdated packages** are not yet checked. Registry lookups (e.g. to determine the latest stable version) are not implemented in v0.1.3.
- **OSV rate limits**: OSV.dev has generous but undocumented rate limits. In practice, the batch API handles hundreds of packages per request without issues.

---

## OSV data license

OSV vulnerability data is made available under the [Creative Commons Attribution 4.0 (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/) license.

DevFoundry queries OSV at runtime but does **not** store, embed, or redistribute advisory data in this repository. No attribution change to the project `LICENSE` file is required.

---

## CLI reference

```bash
# Full scan with OSV (default)
foundry doctor

# Full scan, skip advisory network check
foundry doctor --offline

# Dependency analysis only, with OSV
foundry doctor --dependencies

# Dependency analysis only, skip advisories
foundry doctor --dependencies --offline

# JSON output (includes advisoryInfo field)
foundry doctor --json

# All of the above can be combined with --strict
foundry doctor --strict
foundry doctor --strict --offline
foundry doctor --strict --json
```

### JSON output: `advisoryInfo` field

```json
{
  "advisories": { ... },
  "advisoryInfo": {
    "provider": "osv",
    "status": "ok"
  }
}
```

Offline:
```json
{
  "advisoryInfo": {
    "provider": "none",
    "status": "not_checked"
  }
}
```

Network failure:
```json
{
  "advisoryInfo": {
    "provider": "osv",
    "status": "unavailable",
    "detail": "OSV API request timed out after 15000ms"
  }
}
```
