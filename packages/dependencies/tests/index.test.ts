import { describe, it, expect, vi } from 'vitest';
import { analyzeDependencies, scanVulnerableDependencies, Advisory } from '../src/index.js';
import * as fs from 'node:fs';

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return {
    ...actual,
    existsSync: vi.fn(),
    readFileSync: vi.fn(),
  };
});

describe('dependencies analyzer', () => {
  it('should analyze dependencies and read package-lock.json versions', async () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockImplementation((filePath: string) => {
      if (filePath.endsWith('package.json')) {
        return JSON.stringify({
          dependencies: {
            'lodash': '^4.17.21'
          },
          devDependencies: {
            'typescript': '^5.0.0'
          }
        });
      }
      if (filePath.endsWith('package-lock.json')) {
        return JSON.stringify({
          packages: {
            'node_modules/lodash': { version: '4.17.21' },
            'node_modules/typescript': { version: '5.0.4' }
          }
        });
      }
      return '';
    });

    const analysis = await analyzeDependencies({
      basePath: '.',
      files: ['package.json', 'package-lock.json']
    });

    expect(analysis.packageManager).toBe('npm');
    expect(analysis.dependencies.length).toBe(2);
    expect(analysis.dependencies[0].name).toBe('lodash');
    expect(analysis.dependencies[0].installedVersion).toBe('4.17.21');
    expect(analysis.dependencies[1].name).toBe('typescript');
    expect(analysis.dependencies[1].installedVersion).toBe('5.0.4');
    expect(analysis.dependencies[1].isDev).toBe(true);
  });

  it('should flag vulnerable dependencies matching advisories', () => {
    const analysis = {
      dependencies: [
        { name: 'lodash', versionSpec: '^4.17.21', installedVersion: '4.17.20', isDev: false }
      ]
    };
    const advisories: Advisory[] = [
      { id: '123', dependencyName: 'lodash', vulnerableRange: '<4.17.21', patchedVersion: '4.17.21', severity: 'high', title: 'Prototype Pollution' }
    ];

    const findings = scanVulnerableDependencies(analysis, advisories);
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe('vuln-123');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].message).toContain('Prototype Pollution');
  });
});
