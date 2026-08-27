# CI Policy Engine and GitHub Actions Integration

DevFoundry provides a deterministic **CI Policy Engine** designed to evaluate codebase health policies during automated CI/CD builds.

---

## The Policy Model

DevFoundry policies evaluate findings in your codebase against predefined health constraints.

The default CI policy enforces the following rules for **newly introduced findings**:
1. **No NEW findings** (fails the build if any new finding of any severity is introduced).
2. **No new CRITICAL findings**.
3. **No new HIGH dependency vulnerability findings**.
4. **No new HIGH or CRITICAL secret findings**.

---

## Baseline-Aware CI

DevFoundry CI is **baseline-aware**:
- **Ignored/Whitelisted existing issues**: Any finding already saved in `.devfoundry/baseline.json` is classified as *remaining* and is exempt from policy violations.
- **Fail on regressions**: The policy checks only apply to *new* findings. This allows teams to adopt DevFoundry on legacy projects with existing issues, and immediately block any *new* credentials or vulnerabilities from entering the codebase.

---

## Privacy and Zero Cloud Uploads

> [!IMPORTANT]
> **DevFoundry does not upload repository contents.**
> All scans and comparisons run entirely inside your CI runner. When checking dependency vulnerabilities, only public metadata (package name, version, and ecosystem) is queried against OSV.dev. Source files and credentials never leave the runner.

---

## CLI Reference

### `foundry ci`

Runs diagnostics and compares the current codebase health against the saved baseline, executing the default policy check.

```bash
foundry ci
foundry ci --strict   # Scan all folders including test/fixture files
foundry ci --offline  # Run CI policy checks without querying OSV
```

### Options:
- **`--strict`**: Scan all files including test and fixture folders.
- **`--offline`**: Skip OSV network check.
- **`--json`**: Output stable, machine-readable CI result JSON.

---

## Exit Codes

DevFoundry uses standard exit codes to signal success or failure to CI runners:

- **`0`**: **PASSED** (no policy violations detected).
- **`1`**: **FAILED/PARTIAL** (policy violations detected, new findings introduced, or configured critical/high violations).

### Offline and Advisory-Unavailable Semantics

If the OSV database is unreachable (e.g. network failure) or if checking was explicitly skipped with `--offline`:
- **Build does not fail solely on network loss**: If no new findings exist, the policy evaluation passes (`PASSED` status, exit `0`).
- **Resolution uncertainty**: You cannot confirm that previous dependency vulnerabilities are resolved. These are marked as `uncertain` and the verification part is marked as `partial`.

---

## GitHub Actions Integration

### Using the CI Command in custom workflows
Add DevFoundry to your existing workflow after building the workspace:

```yaml
      - name: Run DevFoundry CI Policy check
        run: node apps/cli/bin/foundry.js ci
```

### Using the composite action
Alternatively, you can call the action directly:

```yaml
      - name: DevFoundry Scan Action
        uses: sivakumarpinnasi/devfoundry@community-dev
        with:
          strict: false
          offline: false
```
