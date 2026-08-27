/**
 * @devfoundry/verification baseline unit tests.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  createBaseline,
  writeBaseline,
  readBaseline,
  clearBaseline,
  mapFindingToBaseline,
  mapBaselineToFinding,
} from '../src/baseline.js';
import type { Finding } from '@devfoundry/core';

const tempPath = path.resolve(__dirname, 'temp-workspace');

beforeEach(() => {
  if (fs.existsSync(tempPath)) {
    fs.rmSync(tempPath, { recursive: true, force: true });
  }
  fs.mkdirSync(tempPath, { recursive: true });
});

afterEach(() => {
  if (fs.existsSync(tempPath)) {
    fs.rmSync(tempPath, { recursive: true, force: true });
  }
});

const mockFinding: Finding = {
  ruleId: 'github-token',
  category: 'security',
  severity: 'critical',
  message: 'Potential GitHub token detected (value: ghp_abc123)',
  file: 'src/secret.js',
  line: 4,
  confidence: 'high',
  fingerprint: 'fp-token',
  remediation: 'Revoke key immediately.',
};

describe('baseline mapping', () => {
  it('omits message and remediation from baseline findings (no leak)', () => {
    const bf = mapFindingToBaseline(mockFinding);
    expect(bf.fingerprint).toBe('fp-token');
    expect(bf.ruleId).toBe('github-token');
    expect(bf.category).toBe('security');
    expect(bf.severity).toBe('critical');
    expect(bf.file).toBe('src/secret.js');
    expect(bf.line).toBe(4);
    // message and remediation MUST be absent / undefined
    expect((bf as unknown as Record<string, unknown>).message).toBeUndefined();
    expect((bf as unknown as Record<string, unknown>).remediation).toBeUndefined();
  });

  it('maps BaselineFinding back to a minimal Finding representation', () => {
    const bf = mapFindingToBaseline(mockFinding);
    const f = mapBaselineToFinding(bf);

    expect(f.fingerprint).toBe('fp-token');
    expect(f.ruleId).toBe('github-token');
    expect(f.category).toBe('security');
    expect(f.severity).toBe('critical');
    expect(f.file).toBe('src/secret.js');
    expect(f.line).toBe(4);
    // Should have safe fallback message and remediation
    expect(f.message).toContain('github-token');
    expect(f.message).not.toContain('ghp_abc123'); // no leakage
    expect(f.remediation).toBeDefined();
  });
});

describe('baseline filesystem management', () => {
  it('creates and writes a baseline to disk', () => {
    const baseline = createBaseline(
      [mockFinding],
      { type: 'Node.js', packageManager: 'pnpm' },
      { provider: 'osv', status: 'ok' },
      '0.1.6'
    );

    writeBaseline(tempPath, baseline);

    const baselineJsonPath = path.join(tempPath, '.devfoundry', 'baseline.json');
    expect(fs.existsSync(baselineJsonPath)).toBe(true);

    const saved = JSON.parse(fs.readFileSync(baselineJsonPath, 'utf8'));
    expect(saved.version).toBe(1);
    expect(saved.toolVersion).toBe('0.1.6');
    expect(saved.project.type).toBe('Node.js');
    expect(saved.project.packageManager).toBe('pnpm');
    expect(saved.findings).toHaveLength(1);
    expect(saved.findings[0].fingerprint).toBe('fp-token');
    expect(saved.findings[0].message).toBeUndefined();
    expect(saved.advisories.provider).toBe('osv');
    expect(saved.advisories.status).toBe('ok');
  });

  it('reads a saved baseline from disk', () => {
    const baseline = createBaseline(
      [mockFinding],
      { type: 'Node.js', packageManager: 'npm' },
      { provider: 'osv', status: 'ok' },
      '0.1.6'
    );

    writeBaseline(tempPath, baseline);

    const loaded = readBaseline(tempPath);
    expect(loaded).not.toBeNull();
    expect(loaded!.version).toBe(1);
    expect(loaded!.project.type).toBe('Node.js');
    expect(loaded!.findings).toHaveLength(1);
    expect(loaded!.findings[0].fingerprint).toBe('fp-token');
  });

  it('returns null if baseline file does not exist', () => {
    const loaded = readBaseline(tempPath);
    expect(loaded).toBeNull();
  });

  it('clears a saved baseline and removes empty directory', () => {
    const baseline = createBaseline(
      [mockFinding],
      { type: 'Node.js', packageManager: 'npm' },
      { provider: 'osv', status: 'ok' },
      '0.1.6'
    );

    writeBaseline(tempPath, baseline);
    const baselineDir = path.join(tempPath, '.devfoundry');
    const baselineJsonPath = path.join(baselineDir, 'baseline.json');

    expect(fs.existsSync(baselineJsonPath)).toBe(true);

    const cleared = clearBaseline(tempPath);
    expect(cleared).toBe(true);
    expect(fs.existsSync(baselineJsonPath)).toBe(false);
    expect(fs.existsSync(baselineDir)).toBe(false); // empty dir cleaned up
  });

  it('returns false when trying to clear a non-existent baseline', () => {
    const cleared = clearBaseline(tempPath);
    expect(cleared).toBe(false);
  });
});
