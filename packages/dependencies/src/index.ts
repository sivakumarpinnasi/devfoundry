import * as fs from 'node:fs';
import * as path from 'node:path';
import { AnalysisContext, Finding } from '@devfoundry/core';

export interface Dependency {
  name: string;
  versionSpec: string;
  installedVersion?: string;
  isDev: boolean;
}

export interface DependencyAnalysis {
  dependencies: Dependency[];
  packageManager?: string;
}

export interface Advisory {
  id: string;
  dependencyName: string;
  vulnerableRange: string;
  patchedVersion: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
}

// Helper to extract version from pnpm-lock.yaml or yarn.lock using regex
function extractFromLockfile(content: string, name: string): string | undefined {
  // Try pnpm-lock.yaml format: "/react@18.2.0" or similar
  const pnpmRegex = new RegExp(`[\\s"/]${name.replace('/', '\\/')}@([^:\\s"\\(\\)]+)`, 'i');
  let match = content.match(pnpmRegex);
  if (match) {
    return match[1];
  }

  // Try yarn.lock format: "react@^18.2.0" followed by version line
  const yarnRegex = new RegExp(`"${name.replace('/', '\\/')}[^"]+":\\s*\\n\\s*version\\s+"([^"]+)"`, 'i');
  match = content.match(yarnRegex);
  if (match) {
    return match[1];
  }
  
  const yarnRegexAlternative = new RegExp(`"${name.replace('/', '\\/')}[^"]+":\\s*version\\s*"([^"]+)"`, 'i');
  match = content.match(yarnRegexAlternative);
  if (match) {
    return match[1];
  }

  return undefined;
}

export async function analyzeDependencies(context: AnalysisContext): Promise<DependencyAnalysis> {
  const result: DependencyAnalysis = {
    dependencies: [],
  };

  const files = context.files;
  const packageJsonFile = files.find(f => f === 'package.json' || f.endsWith('/package.json') || f.endsWith('\\package.json'));
  if (!packageJsonFile) {
    return result;
  }

  const fullPath = path.isAbsolute(packageJsonFile) ? packageJsonFile : path.join(context.basePath, packageJsonFile);
  if (!fs.existsSync(fullPath)) {
    return result;
  }

  try {
    const pkgContent = fs.readFileSync(fullPath, 'utf8');
    const pkg = JSON.parse(pkgContent);
    
    // Determine package manager
    if (files.some(f => f.endsWith('pnpm-lock.yaml'))) result.packageManager = 'pnpm';
    else if (files.some(f => f.endsWith('yarn.lock'))) result.packageManager = 'yarn';
    else if (files.some(f => f.endsWith('bun.lockb') || f.endsWith('bun.lock'))) result.packageManager = 'bun';
    else if (files.some(f => f.endsWith('package-lock.json'))) result.packageManager = 'npm';

    const dependenciesList: Dependency[] = [];

    // Parse dependencies
    const deps = pkg.dependencies || {};
    const devDeps = pkg.devDependencies || {};

    // Load lockfile content if available
    let lockfileContent = '';
    interface PackageLock {
      packages?: Record<string, { version?: string }>;
      dependencies?: Record<string, { version?: string }>;
    }
    let packageLockJson: PackageLock | null = null;

    if (result.packageManager === 'npm') {
      const lockFile = files.find(f => f.endsWith('package-lock.json'));
      if (lockFile) {
        const lockPath = path.isAbsolute(lockFile) ? lockFile : path.join(context.basePath, lockFile);
        if (fs.existsSync(lockPath)) {
          try {
            packageLockJson = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
          } catch {
            /* ignore read/parse errors */
          }
        }
      }
    } else if (result.packageManager) {
      const lockFile = files.find(f => f.endsWith('pnpm-lock.yaml') || f.endsWith('yarn.lock'));
      if (lockFile) {
        const lockPath = path.isAbsolute(lockFile) ? lockFile : path.join(context.basePath, lockFile);
        if (fs.existsSync(lockPath)) {
          try {
            lockfileContent = fs.readFileSync(lockPath, 'utf8');
          } catch {
            /* ignore read errors */
          }
        }
      }
    }

    const processDep = (name: string, spec: string, isDev: boolean) => {
      let installedVersion: string | undefined;

      if (packageLockJson) {
        // package-lock.json v2/v3 has packages keys
        const pkgKey = `node_modules/${name}`;
        if (packageLockJson.packages && packageLockJson.packages[pkgKey]) {
          installedVersion = packageLockJson.packages[pkgKey].version;
        } else if (packageLockJson.dependencies && packageLockJson.dependencies[name]) {
          installedVersion = packageLockJson.dependencies[name].version;
        }
      } else if (lockfileContent) {
        installedVersion = extractFromLockfile(lockfileContent, name);
      }

      dependenciesList.push({
        name,
        versionSpec: spec,
        installedVersion,
        isDev,
      });
    };

    for (const [name, spec] of Object.entries(deps)) {
      processDep(name, spec as string, false);
    }
    for (const [name, spec] of Object.entries(devDeps)) {
      processDep(name, spec as string, true);
    }

    result.dependencies = dependenciesList;
  } catch {
    // Ignore parse errors
  }

  return result;
}

// Future advisory check engine stub (returns findings based on matching lockfile/dep versions)
export function scanVulnerableDependencies(analysis: DependencyAnalysis, advisories: Advisory[]): Finding[] {
  const findings: Finding[] = [];
  
  for (const dep of analysis.dependencies) {
    const version = dep.installedVersion || dep.versionSpec;
    // Simple direct matching or semver matching for future integration
    const matchedAdvisory = advisories.find(a => a.dependencyName === dep.name);
    if (matchedAdvisory) {
      findings.push({
        ruleId: `vuln-${matchedAdvisory.id}`,
        severity: matchedAdvisory.severity,
        message: `Dependency "${dep.name}" (${version}) has a known vulnerability: ${matchedAdvisory.title}`,
        file: 'package.json',
      });
    }
  }

  return findings;
}
