import { describe, it, expect } from 'vitest';
import { scanSecurity } from '../src/index.js';

describe('security', () => {
  it('should scan and find zero secrets/issues by default', () => {
    const result = scanSecurity();
    expect(result.secrets).toBe(0);
    expect(result.issues).toBe(0);
  });
});
