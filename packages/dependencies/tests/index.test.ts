import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'node:fs';

import {
  analyzeDependencies,
  scanWithAdvisories,
  MockAdvisoryProvider,
  NoOpAdvisoryProvider,
  parseManifest,
  parseNpmLockfile,
  parsePnpmLockfile,
  parseYarnLockfile,
  DependencyAdvisory,
} from '../src/index.js';

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return {
    ...actual,
    existsSync: vi.fn(),
    readFileSync: vi.fn(),
  };
});

afterEach(() => {
  vi.clearAllMocks();
});

// ---------------------------------------------------------------------------
// manifest.ts
// ---------------------------------------------------------------------------
describe('parseManifest', () => {
  it('returns empty array for missing file', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(false);
    expect(parseManifest('/nonexistent/package.json')).toEqual([]);
  });

  it('returns empty array for malformed JSON', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockReturnValue('NOT JSON' as unknown as Buffer);
    expect(parseManifest('/bad/package.json')).toEqual([]);
  });

  it('parses all four dependency sections', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify({
      dependencies: { lodash: '^4.17.21' },
      devDependencies: { typescript: '^5.0.0' },
      optionalDependencies: { fsevents: '^2.3.0' },
      peerDependencies: { react: '>=18' },
    }) as unknown as Buffer);
    const deps = parseManifest('/project/package.json');
    expect(deps).toHaveLength(4);
    expect(deps.find(d => d.name === 'lodash')?.depType).toBe('production');
    expect(deps.find(d => d.name === 'typescript')?.depType).toBe('dev');
    expect(deps.find(d => d.name === 'fsevents')?.depType).toBe('optional');
    expect(deps.find(d => d.name === 'react')?.depType).toBe('peer');
    // All are direct
    expect(deps.every(d => d.direct === 'direct')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// lockfile/npm.ts
// ---------------------------------------------------------------------------
describe('parseNpmLockfile', () => {
  it('returns empty on missing file', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(false);
    const result = parseNpmLockfile('/missing/package-lock.json');
    expect(result.resolvedVersions.size).toBe(0);
  });

  it('returns empty on malformed JSON', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockReturnValue('BAD JSON' as unknown as Buffer);
    const result = parseNpmLockfile('/bad/package-lock.json');
    expect(result.resolvedVersions.size).toBe(0);
  });

  it('parses v3 packages section', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'root' },
        'node_modules/express': { version: '4.18.2' },
        'node_modules/ms': { version: '2.1.3' },
      },
    }) as unknown as Buffer);
    const result = parseNpmLockfile('/proj/package-lock.json');
    expect(result.resolvedVersions.get('express')).toBe('4.18.2');
    expect(result.resolvedVersions.get('ms')).toBe('2.1.3');
    expect(result.allLockfileNames.has('express')).toBe(true);
    expect(result.allLockfileNames.has('ms')).toBe(true);
  });

  it('parses v1 dependencies section', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        lodash: { version: '4.17.20' },
      },
    }) as unknown as Buffer);
    const result = parseNpmLockfile('/proj/package-lock.json');
    expect(result.resolvedVersions.get('lodash')).toBe('4.17.20');
  });
});

// ---------------------------------------------------------------------------
// lockfile/pnpm.ts
// ---------------------------------------------------------------------------
describe('parsePnpmLockfile', () => {
  it('returns empty on missing file', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(false);
    const result = parsePnpmLockfile('/missing/pnpm-lock.yaml');
    expect(result.resolvedVersions.size).toBe(0);
  });

  it('parses v6 format with packages and importers', () => {
    const yaml = `lockfileVersion: '6.0'
importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21
    devDependencies:
      typescript:
        specifier: ^5.0.0
        version: 5.0.4
packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-fake==}
    dev: false
  /typescript@5.0.4:
    resolution: {integrity: sha512-fake==}
    dev: true
  /inherits@2.0.4:
    resolution: {integrity: sha512-fake==}
    dev: false
`;
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(yaml as unknown as Buffer);
    const result = parsePnpmLockfile('/proj/pnpm-lock.yaml');
    expect(result.resolvedVersions.get('lodash')).toBe('4.17.21');
    expect(result.resolvedVersions.get('typescript')).toBe('5.0.4');
    expect(result.allLockfileNames.has('inherits')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// lockfile/yarn.ts
// ---------------------------------------------------------------------------
describe('parseYarnLockfile', () => {
  it('returns empty on missing file', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(false);
    const result = parseYarnLockfile('/missing/yarn.lock');
    expect(result.resolvedVersions.size).toBe(0);
  });

  it('parses classic yarn.lock v1', () => {
    const content = `# THIS IS AN AUTOGENERATED FILE.
# yarn lockfile v1

axios@^1.4.0:
  version "1.4.0"
  resolved "https://registry.yarnpkg.com/axios/-/axios-1.4.0.tgz#fake"

follow-redirects@^1.15.0:
  version "1.15.2"
  resolved "https://registry.yarnpkg.com/follow-redirects/-/follow-redirects-1.15.2.tgz#fake"
`;
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(content as unknown as Buffer);
    const result = parseYarnLockfile('/proj/yarn.lock');
    expect(result.resolvedVersions.get('axios')).toBe('1.4.0');
    expect(result.resolvedVersions.get('follow-redirects')).toBe('1.15.2');
    expect(result.allLockfileNames.has('follow-redirects')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// analyzeDependencies — integration
// ---------------------------------------------------------------------------
describe('analyzeDependencies', () => {
  it('analyzes npm project with direct and transitive deps', async () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockImplementation((filePath) => {
      const fp = String(filePath);
      if (fp.endsWith('package.json') && !fp.endsWith('package-lock.json')) {
        return JSON.stringify({ dependencies: { express: '^4.18.2' }, devDependencies: { jest: '^29.0.0' } }) as unknown as Buffer;
      }
      if (fp.endsWith('package-lock.json')) {
        return JSON.stringify({
          lockfileVersion: 3,
          packages: {
            '': {},
            'node_modules/express': { version: '4.18.2' },
            'node_modules/jest': { version: '29.6.1', dev: true },
            'node_modules/ms': { version: '2.1.3' },
          },
        }) as unknown as Buffer;
      }
      return '' as unknown as Buffer;
    });

    const analysis = await analyzeDependencies({
      basePath: '/proj',
      files: ['package.json', 'package-lock.json'],
    });

    expect(analysis.packageManager).toBe('npm');
    const express = analysis.dependencies.find(d => d.name === 'express');
    expect(express?.installedVersion).toBe('4.18.2');
    expect(express?.direct).toBe('direct');
    expect(express?.depType).toBe('production');

    const ms = analysis.dependencies.find(d => d.name === 'ms');
    expect(ms?.direct).toBe('transitive');
    expect(ms?.installedVersion).toBe('2.1.3');

    expect(analysis.metrics.direct).toBeGreaterThanOrEqual(2); // express + jest
    expect(analysis.metrics.transitive).toBeGreaterThanOrEqual(1); // ms
    expect(analysis.metrics.total).toBe(analysis.metrics.direct + analysis.metrics.transitive);
  });

  it('resolves installed version from lockfile, not from package.json spec', async () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockImplementation((filePath) => {
      const fp = String(filePath);
      if (fp.endsWith('package.json') && !fp.endsWith('package-lock.json')) {
        return JSON.stringify({ dependencies: { lodash: '^4.17.21' } }) as unknown as Buffer;
      }
      if (fp.endsWith('package-lock.json')) {
        return JSON.stringify({
          lockfileVersion: 2,
          packages: { 'node_modules/lodash': { version: '4.17.21' } },
        }) as unknown as Buffer;
      }
      return '' as unknown as Buffer;
    });

    const analysis = await analyzeDependencies({ basePath: '.', files: ['package.json', 'package-lock.json'] });
    const lodash = analysis.dependencies.find(d => d.name === 'lodash');
    // Must be 4.17.21 (from lockfile), not '^4.17.21' (from package.json spec)
    expect(lodash?.installedVersion).toBe('4.17.21');
    expect(lodash?.versionSpec).toBe('^4.17.21');
  });

  it('analyzes pnpm project with transitive dep', async () => {
    const yaml = `lockfileVersion: '6.0'
importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21
packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-fake}
    dev: false
  /inherits@2.0.4:
    resolution: {integrity: sha512-fake}
    dev: false
`;
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockImplementation((filePath) => {
      const fp = String(filePath);
      if (fp.endsWith('package.json')) return JSON.stringify({ dependencies: { lodash: '^4.17.21' } }) as unknown as Buffer;
      if (fp.endsWith('pnpm-lock.yaml')) return yaml as unknown as Buffer;
      return '' as unknown as Buffer;
    });

    const analysis = await analyzeDependencies({ basePath: '.', files: ['package.json', 'pnpm-lock.yaml'] });
    expect(analysis.packageManager).toBe('pnpm');
    expect(analysis.dependencies.find(d => d.name === 'lodash')?.direct).toBe('direct');
    expect(analysis.dependencies.find(d => d.name === 'inherits')?.direct).toBe('transitive');
  });

  it('analyzes yarn project', async () => {
    const lock = `# yarn lockfile v1

axios@^1.4.0:
  version "1.4.0"

follow-redirects@^1.15.0:
  version "1.15.2"
`;
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockImplementation((filePath) => {
      const fp = String(filePath);
      if (fp.endsWith('package.json')) return JSON.stringify({ dependencies: { axios: '^1.4.0' } }) as unknown as Buffer;
      if (fp.endsWith('yarn.lock')) return lock as unknown as Buffer;
      return '' as unknown as Buffer;
    });

    const analysis = await analyzeDependencies({ basePath: '.', files: ['package.json', 'yarn.lock'] });
    expect(analysis.packageManager).toBe('yarn');
    expect(analysis.dependencies.find(d => d.name === 'axios')?.installedVersion).toBe('1.4.0');
    expect(analysis.dependencies.find(d => d.name === 'follow-redirects')?.direct).toBe('transitive');
  });

  it('handles malformed lockfile gracefully', async () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockImplementation((filePath) => {
      const fp = String(filePath);
      if (fp.endsWith('package.json') && !fp.endsWith('package-lock.json')) {
        return JSON.stringify({ dependencies: { lodash: '^4.17.21' } }) as unknown as Buffer;
      }
      if (fp.endsWith('package-lock.json')) return 'NOT JSON AT ALL' as unknown as Buffer;
      return '' as unknown as Buffer;
    });

    const analysis = await analyzeDependencies({ basePath: '.', files: ['package.json', 'package-lock.json'] });
    // Should still return manifest deps, just without resolved versions
    expect(analysis.dependencies.find(d => d.name === 'lodash')?.versionSpec).toBe('^4.17.21');
    expect(analysis.dependencies.find(d => d.name === 'lodash')?.installedVersion).toBeUndefined();
  });

  it('returns empty result when no package.json', async () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(false);
    const analysis = await analyzeDependencies({ basePath: '.', files: [] });
    expect(analysis.dependencies).toHaveLength(0);
    expect(analysis.metrics.total).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// advisory scanning
// ---------------------------------------------------------------------------
describe('scanWithAdvisories', () => {
  it('reports vulnerability from mock provider', async () => {
    const advisory: DependencyAdvisory = {
      id: 'ADV-001',
      dependencyName: 'lodash',
      vulnerableRange: '<4.17.21',
      fixedVersion: '4.17.21',
      severity: 'high',
      summary: 'Prototype Pollution in lodash',
      source: 'mock',
      remediation: 'Upgrade to 4.17.21+',
    };
    const provider = new MockAdvisoryProvider([advisory]);
    const analysis = {
      dependencies: [
        { name: 'lodash', versionSpec: '^4.17.21', installedVersion: '4.17.20', depType: 'production' as const, direct: 'direct' as const, source: 'package.json' },
      ],
      packageManager: 'npm',
      metrics: { total: 1, direct: 1, transitive: 0, outdated: 0, vulnerable: 0 },
    };

    const result = await scanWithAdvisories(analysis, provider);
    expect(result.advisoryInfo.status).toBe('ok');
    expect(result.advisoryInfo.provider).toBe('mock');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].ruleId).toBe('vuln-ADV-001');
    expect(result.findings[0].category).toBe('dependencies');
    expect(result.findings[0].severity).toBe('high');
    expect(result.findings[0].message).toContain('lodash');
    expect(result.findings[0].message).toContain('Prototype Pollution');
    expect(result.findings[0].fingerprint).toBeDefined();
    expect(result.findings[0].remediation).toContain('4.17.21');
  });

  it('does not report finding for non-matching package', async () => {
    const advisory: DependencyAdvisory = {
      id: 'ADV-002',
      dependencyName: 'axios',
      vulnerableRange: '<1.0.0',
      severity: 'medium',
      summary: 'SSRF in old axios',
      source: 'mock',
    };
    const provider = new MockAdvisoryProvider([advisory]);
    const analysis = {
      dependencies: [
        { name: 'lodash', versionSpec: '^4.17.21', installedVersion: '4.17.21', depType: 'production' as const, direct: 'direct' as const, source: 'package.json' },
      ],
      packageManager: 'npm',
      metrics: { total: 1, direct: 1, transitive: 0, outdated: 0, vulnerable: 0 },
    };

    const result = await scanWithAdvisories(analysis, provider);
    expect(result.findings).toHaveLength(0);
  });

  it('deduplicates advisory findings for the same dep', async () => {
    const advisory: DependencyAdvisory = {
      id: 'ADV-003',
      dependencyName: 'lodash',
      vulnerableRange: '<4.17.21',
      severity: 'high',
      summary: 'Prototype Pollution',
      source: 'mock',
    };
    // Two entries for the same package (e.g. direct + transitive alias)
    const analysis = {
      dependencies: [
        { name: 'lodash', versionSpec: '^4.0.0', installedVersion: '4.17.20', depType: 'production' as const, direct: 'direct' as const, source: 'package.json' },
        { name: 'lodash', versionSpec: '^4.0.0', installedVersion: '4.17.20', depType: 'production' as const, direct: 'transitive' as const, source: 'lockfile' },
      ],
      packageManager: 'npm',
      metrics: { total: 2, direct: 1, transitive: 1, outdated: 0, vulnerable: 0 },
    };
    const provider = new MockAdvisoryProvider([advisory]);
    const result = await scanWithAdvisories(analysis, provider);
    expect(result.findings).toHaveLength(1); // deduplicated
  });

  it('NoOpAdvisoryProvider returns no findings', async () => {
    const provider = new NoOpAdvisoryProvider();
    const analysis = {
      dependencies: [
        { name: 'lodash', versionSpec: '^4.17.21', installedVersion: '4.17.21', depType: 'production' as const, direct: 'direct' as const, source: 'package.json' },
      ],
      packageManager: 'npm',
      metrics: { total: 1, direct: 1, transitive: 0, outdated: 0, vulnerable: 0 },
    };
    const result = await scanWithAdvisories(analysis, provider);
    expect(result.findings).toHaveLength(0);
    expect(result.advisoryInfo.status).toBe('not_checked');
    expect(result.advisoryInfo.provider).toBe('none');
  });
});
