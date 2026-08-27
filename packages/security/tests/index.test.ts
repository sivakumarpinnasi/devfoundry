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

  it('should scan files and detect secrets', async () => {
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

    expect(findings.length).toBe(3);
    const ruleIds = findings.map(f => f.ruleId);
    expect(ruleIds).toContain('github-token');
    expect(ruleIds).toContain('aws-access-key');
    expect(ruleIds).toContain('generic-api-key');
    expect(findings[1].ruleId).toBe('aws-access-key');
    expect(findings[1].message).toContain('AKIA...MPLE');
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
