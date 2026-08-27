/**
 * @devfoundry/dependencies — public entry point
 *
 * Orchestrates manifest parsing, lockfile parsing, version resolution,
 * and advisory scanning into a single analyzeDependencies() call.
 *
 * Re-exports all types and sub-module functions for external consumers.
 */
import * as path from 'node:path';
import { AnalysisContext } from '@devfoundry/core';

import { parseManifest } from './manifest.js';
import { parseNpmLockfile } from './lockfile/npm.js';
import { parsePnpmLockfile } from './lockfile/pnpm.js';
import { parseYarnLockfile } from './lockfile/yarn.js';
import { resolveDependencies } from './resolver.js';
import { DependencyAnalysis } from './model.js';

// Re-export everything consumers may need
export * from './model.js';
export * from './manifest.js';
export * from './lockfile/npm.js';
export * from './lockfile/pnpm.js';
export * from './lockfile/yarn.js';
export * from './resolver.js';
export * from './advisory.js';
export * from './providers/osv.js';

/**
 * Determine the package manager from the list of files in context.
 */
function detectPackageManager(files: string[]): string | undefined {
  if (files.some(f => f.endsWith('pnpm-lock.yaml'))) return 'pnpm';
  if (files.some(f => f.endsWith('yarn.lock'))) return 'yarn';
  if (files.some(f => f.endsWith('bun.lockb') || f.endsWith('bun.lock'))) return 'bun';
  if (files.some(f => f.endsWith('package-lock.json'))) return 'npm';
  return undefined;
}

/**
 * Full dependency analysis for a project.
 *
 * Reads package.json, resolves versions from the appropriate lockfile,
 * and computes dependency metrics.
 *
 * Advisory scanning is NOT performed here — call scanWithAdvisories()
 * separately with your chosen DependencyAdvisoryProvider.
 */
export async function analyzeDependencies(context: AnalysisContext): Promise<DependencyAnalysis> {
  const empty: DependencyAnalysis = {
    dependencies: [],
    metrics: { total: 0, direct: 0, transitive: 0, outdated: 0, vulnerable: 0 },
  };

  const files = context.files;

  // Locate package.json
  const packageJsonFile = files.find(
    f => f === 'package.json' || f.endsWith('/package.json') || f.endsWith('\\package.json'),
  );
  if (!packageJsonFile) return empty;

  const packageJsonPath = path.isAbsolute(packageJsonFile)
    ? packageJsonFile
    : path.join(context.basePath, packageJsonFile);

  const packageManager = detectPackageManager(files);
  const manifestDeps = parseManifest(packageJsonPath);

  // Parse the appropriate lockfile
  let resolvedVersions = new Map<string, string>();
  let allLockfileNames = new Set<string>();

  if (packageManager === 'npm') {
    const lockFile = files.find(f => f.endsWith('package-lock.json'));
    if (lockFile) {
      const lockPath = path.isAbsolute(lockFile) ? lockFile : path.join(context.basePath, lockFile);
      const result = parseNpmLockfile(lockPath);
      resolvedVersions = result.resolvedVersions;
      allLockfileNames = result.allLockfileNames;
    }
  } else if (packageManager === 'pnpm') {
    const lockFile = files.find(f => f.endsWith('pnpm-lock.yaml'));
    if (lockFile) {
      const lockPath = path.isAbsolute(lockFile) ? lockFile : path.join(context.basePath, lockFile);
      const result = parsePnpmLockfile(lockPath);
      resolvedVersions = result.resolvedVersions;
      allLockfileNames = result.allLockfileNames;
    }
  } else if (packageManager === 'yarn') {
    const lockFile = files.find(f => f.endsWith('yarn.lock'));
    if (lockFile) {
      const lockPath = path.isAbsolute(lockFile) ? lockFile : path.join(context.basePath, lockFile);
      const result = parseYarnLockfile(lockPath);
      resolvedVersions = result.resolvedVersions;
      allLockfileNames = result.allLockfileNames;
    }
  }

  return resolveDependencies({ manifestDeps, resolvedVersions, allLockfileNames, packageManager });
}
