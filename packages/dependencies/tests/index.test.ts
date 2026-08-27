import { describe, it, expect } from 'vitest';
import { checkDependencies } from '../src/index.js';

describe('dependencies', () => {
  it('should check dependencies and find zero issues by default', () => {
    const result = checkDependencies();
    expect(result.vulnerable).toBe(0);
    expect(result.outdated).toBe(0);
  });
});
