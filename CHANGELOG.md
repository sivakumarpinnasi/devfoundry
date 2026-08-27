# Changelog

All notable changes to DevFoundry will be documented in this file.

---

## [0.2.0] - 2026-08-27

### Added
- **Unified AnalysisPipeline Orchestration**: Core pipeline driving detection, scanning, and verification.
- **`foundry scan`**: Complete scanning subcommand with structured scoring and full project insights.
- **RuleRegistry & Pluggable Registry Pattern**: Modularized standard secret detection rules and custom analyzers.
- **Integration Tests**: End-to-end coverage confirming that doctor, scan, verify, fix, and ci commands route through the shared pipeline.

---

## [0.1.8] - 2026-08-20

### Added
- **GitHub PR Integration**: PR annotations and step summaries formatters.
- **PR Status Reporting**: Exposes `passed` / `failed` status for verification, policy, and advisories separately.

---

## [0.1.7] - 2026-08-10

### Added
- **CI Policy Engine**: Policy conditions checking for new findings, secrets, and high-severity dependency vulnerabilities.

---

## [0.1.6] - 2026-08-01

### Added
- **Codebase Baselines**: Support for `--previous` baseline.json files to allow verification flow.

---

## [0.1.5] - 2026-07-20

### Added
- **Verification Engine**: Introduction of `foundry verify` command.

---

## [0.1.4] - 2026-07-05

### Added
- **Remediation Intelligence**: Non-mutating `foundry fix` guidance engine.

---

## [0.1.3] - 2026-06-20

### Added
- **OSV vulnerability database integration** for dependency advisory resolution.

---

## [0.1.2] - 2026-06-05

### Added
- **Dependency parsing support** for npm, pnpm, and yarn lockfiles.
