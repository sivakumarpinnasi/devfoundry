import { describe, it, expect, vi } from 'vitest';
import { scanSecurity, maskSecret } from '../src/index.js';
import * as fs from 'node:fs';

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return {
    ...actual,
    existsSync: vi.fn(),
    readFileSync: vi.fn(),
    statSync: vi.fn(),
  };
});

describe('security secret scanner', () => {
  it('should mask secrets correctly', () => {
    expect(maskSecret('123')).toBe('********');
    expect(maskSecret('ghp_123456789012345678901234567890123456')).toBe('ghp_...3456');
  });

  it('should scan files and detect specific secrets with deduplication', async () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'statSync').mockReturnValue({ isDirectory: () => false } as unknown as fs.Stats);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(`
      const token = "ghp_abc123XYZabc123XYZabc123XYZabc123XYZ";
      const aws = "AKIAIOSFODNN7EXAMPLE";
    `);

    const findings = await scanSecurity({
      basePath: '.',
      files: ['src/config.js']
    });

    // Both match specific rules (github-token, aws-access-key).
    // The generic-api-key matches must be deduplicated out because they overlap!
    expect(findings.length).toBe(2);
    const ruleIds = findings.map(f => f.ruleId);
    expect(ruleIds).toContain('github-token');
    expect(ruleIds).toContain('aws-access-key');
    expect(ruleIds).not.toContain('generic-api-key');
  });

  it('should report generic-api-key when no specific rule overlaps', async () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'statSync').mockReturnValue({ isDirectory: () => false } as unknown as fs.Stats);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(`
      const secret_key = "some-long-unknown-custom-api-key-here-12345";
    `);

    const findings = await scanSecurity({
      basePath: '.',
      files: ['src/config.js']
    });

    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe('generic-api-key');
  });

  it('should skip test/fixture directories in non-strict mode', async () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'statSync').mockReturnValue({ isDirectory: () => false } as unknown as fs.Stats);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(`
      const token = "ghp_abc123XYZabc123XYZabc123XYZabc123XYZ";
    `);

    const findingsNormal = await scanSecurity({
      basePath: '.',
      files: ['tests/index.test.ts', 'fixtures/secrets.js'],
      strict: false
    });
    expect(findingsNormal.length).toBe(0);

    const findingsStrict = await scanSecurity({
      basePath: '.',
      files: ['tests/index.test.ts', 'fixtures/secrets.js'],
      strict: true
    });
    expect(findingsStrict.length).toBe(2);
  });

  it('should skip ignored directories and binary files', async () => {
    const findings = await scanSecurity({
      basePath: '.',
      files: [
        'node_modules/dep/index.js',
        'dist/bundle.js',
        'src/logo.png'
      ]
    });

    expect(findings.length).toBe(0);
  });
});
