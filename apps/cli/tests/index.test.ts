import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { detectProject } from '@devfoundry/detector';
import { scanSecurity } from '@devfoundry/security';
import { analyzeDependencies } from '@devfoundry/dependencies';
import { calculateScore } from '@devfoundry/core';

describe('integration flow with fixtures', () => {
  const fixturesPath = path.resolve(__dirname, '../../../tests/fixtures');

  it('should correctly analyze clean-node fixture', async () => {
    const basePath = path.join(fixturesPath, 'clean-node');
    const files = ['package.json', 'tsconfig.json'];
    const context = { basePath, files };

    const project = await detectProject(context);
    const security = await scanSecurity(context);
    const deps = await analyzeDependencies(context);

    expect(project.type).toBe('Node.js / TypeScript');
    expect(security.length).toBe(0);
    expect(deps.dependencies.length).toBe(1);
    expect(deps.dependencies[0].name).toBe('typescript');
    expect(calculateScore(security)).toBe(100);
  });

  it('should detect secrets in with-secrets fixture', async () => {
    const basePath = path.join(fixturesPath, 'with-secrets');
    const files = ['package.json', 'secrets.js'];
    const context = { basePath, files };

    const project = await detectProject(context);
    const security = await scanSecurity(context);

    expect(project.type).toBe('Node.js');
    expect(security.length).toBeGreaterThanOrEqual(2);
    
    const ruleIds = security.map(f => f.ruleId);
    expect(ruleIds).toContain('github-token');
    expect(ruleIds).toContain('aws-access-key');
    expect(ruleIds).toContain('private-key');
    expect(calculateScore(security)).toBeLessThan(50);
  });

  it('should detect frameworks in with-frameworks fixture', async () => {
    const basePath = path.join(fixturesPath, 'with-frameworks');
    const files = ['package.json', 'next.config.js'];
    const context = { basePath, files };

    const project = await detectProject(context);
    expect(project.frameworks).toContain('Next.js');
    expect(project.frameworks).toContain('React');
  });

  it('should resolve lockfile versions in with-deps fixture', async () => {
    const basePath = path.join(fixturesPath, 'with-deps');
    const files = ['package.json', 'pnpm-lock.yaml'];
    const context = { basePath, files };

    const deps = await analyzeDependencies(context);
    expect(deps.packageManager).toBe('pnpm');
    expect(deps.dependencies.length).toBe(2);
    
    const lodash = deps.dependencies.find(d => d.name === 'lodash');
    expect(lodash?.installedVersion).toBe('4.17.21');

    const ts = deps.dependencies.find(d => d.name === 'typescript');
    expect(ts?.installedVersion).toBe('5.0.4');
  });
});
