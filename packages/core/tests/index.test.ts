import { describe, it, expect } from 'vitest';
import { calculateScore, Finding } from '../src/index.js';

describe('core calculateScore', () => {
  it('should return 100 for no findings', () => {
    expect(calculateScore([])).toBe(100);
  });

  it('should deduct scores correctly based on severity', () => {
    const findings: Finding[] = [
      { ruleId: 'rule1', category: 'security', severity: 'low', message: 'test', file: 'file.js', fingerprint: 'f1' },
      { ruleId: 'rule2', category: 'security', severity: 'medium', message: 'test', file: 'file.js', fingerprint: 'f2' },
      { ruleId: 'rule3', category: 'security', severity: 'high', message: 'test', file: 'file.js', fingerprint: 'f3' },
      { ruleId: 'rule4', category: 'security', severity: 'critical', message: 'test', file: 'file.js', fingerprint: 'f4' },
    ];
    // penalty: 2 + 10 + 20 + 40 = 72. Score: 100 - 72 = 28
    expect(calculateScore(findings)).toBe(28);
  });

  it('should not go below 0', () => {
    const findings: Finding[] = [
      { ruleId: 'rule1', category: 'security', severity: 'critical', message: 'test', file: 'file.js', fingerprint: 'f1' },
      { ruleId: 'rule2', category: 'security', severity: 'critical', message: 'test', file: 'file.js', fingerprint: 'f2' },
      { ruleId: 'rule3', category: 'security', severity: 'critical', message: 'test', file: 'file.js', fingerprint: 'f3' },
    ];
    // penalty: 120. Score: 0
    expect(calculateScore(findings)).toBe(0);
  });
});

describe('core registries & pipeline', () => {
  it('should register and retrieve rule metadata', async () => {
    const { RuleRegistry } = await import('../src/rule.js');
    const registry = RuleRegistry.getInstance();
    const tokenRule = registry.get('github-token');
    expect(tokenRule).toBeDefined();
    expect(tokenRule?.name).toBe('GitHub OAuth/PAT Token');
    expect(tokenRule?.category).toBe('security');
  });

  it('should register and execute pluggable detectors and analyzers in AnalysisPipeline', async () => {
    const { PluginRegistry } = await import('../src/plugin.js');
    const { runAnalysisPipeline } = await import('../src/pipeline.js');

    const pluginRegistry = PluginRegistry.getInstance();
    pluginRegistry.clear();

    pluginRegistry.registerDetector({
      name: 'mock-detector',
      detect: async () => ({ type: 'TypeScript', frameworks: ['React'] }),
    });

    pluginRegistry.registerAnalyzer({
      name: 'mock-analyzer',
      analyze: async () => [
        { ruleId: 'github-token', category: 'security', severity: 'critical', message: 'Token found', file: 'index.js', fingerprint: 'fp-mock' }
      ],
    });

    const result = await runAnalysisPipeline({
      basePath: '/test',
      files: ['index.js'],
    });

    expect(result.schemaVersion).toBe(1);
    expect(result.toolVersion).toBe('0.2.0');
    expect(result.project.type).toBe('TypeScript');
    expect(result.project.frameworks).toContain('React');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].fingerprint).toBe('fp-mock');
    expect(result.score.overallHealth).toBe(60); // 100 - 40 (critical) = 60
  });
});
