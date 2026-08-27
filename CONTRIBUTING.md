# Contributing to DevFoundry

We welcome contributions to DevFoundry! Follow the instructions below to set up your local development environment and submit changes.

## Development Setup

1. **Prerequisites**: Ensure you have [Node.js (v18+)](https://nodejs.org) and [pnpm](https://pnpm.io/) installed.
2. **Install Dependencies**:
   ```bash
   pnpm install
   ```
3. **Build Packages**:
   ```bash
   pnpm build
   ```
4. **Run Tests**:
   ```bash
   pnpm test
   ```
5. **Run Linter**:
   ```bash
   pnpm lint
   ```

## Package Structure

- `apps/cli`: The main entry CLI application (`foundry`).
- `packages/core`: Central scoring, pipeline, and registries.
- `packages/detector`: Framework and project detection.
- `packages/security`: Secret/credential scanner.
- `packages/dependencies`: Dependency intelligence and manifest/lockfile resolvers.
- `packages/verification`: Baseline comparator.
- `packages/policy`: CI policy evaluator.
- `packages/remediation`: Non-mutating remediation planners.
- `packages/reporter`: CLI output and JSON formatting.
- `packages/integrations/github`: GitHub Actions annotations and PR step summary reporter.

## Pull Request Guidelines

- Ensure all code compiles cleanly (`pnpm build`).
- Ensure all tests pass (`pnpm test`).
- Ensure all ESLint checks pass (`pnpm lint`).
- Include test fixtures or coverage for any new features or rules.
- Do not check in active secrets or test credentials.
