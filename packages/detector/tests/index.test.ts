import { describe, it, expect, vi } from 'vitest';
import { detectProject } from '../src/index.js';
import * as fs from 'node:fs';

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return {
    ...actual,
    existsSync: vi.fn(),
    readFileSync: vi.fn(),
  };
});

describe('detector', () => {
  it('should fallback to Unknown for empty context', async () => {
    const result = await detectProject({ basePath: '.', files: [] });
    expect(result.type).toBe('Unknown');
    expect(result.frameworks).toEqual([]);
  });

  it('should detect Node.js / TypeScript project with pnpm package manager', async () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify({
      dependencies: {
        'react': '^18.0.0',
        'next': '^14.0.0'
      }
    }));

    const result = await detectProject({
      basePath: '.',
      files: ['package.json', 'tsconfig.json', 'pnpm-lock.yaml']
    });

    expect(result.type).toBe('Node.js / TypeScript');
    expect(result.packageManager).toBe('pnpm');
    expect(result.frameworks).toContain('React');
    expect(result.frameworks).toContain('Next.js');
  });
});
