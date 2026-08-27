/**
 * Baseline manager for DevFoundry.
 * Handles creation, reading, writing, and clearing of baselines.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Finding, AdvisoryInfo } from '@devfoundry/core';
import type { Baseline, BaselineFinding } from './model.js';

const BASELINE_DIR = '.devfoundry';
const BASELINE_FILE = 'baseline.json';

/** Map a Finding to a non-sensitive BaselineFinding. */
export function mapFindingToBaseline(finding: Finding): BaselineFinding {
  return {
    fingerprint: finding.fingerprint,
    ruleId: finding.ruleId,
    category: finding.category,
    severity: finding.severity,
    file: finding.file,
    line: finding.line,
    // message and remediation are omitted to prevent sensitive credential leak
  };
}

/** Map a BaselineFinding back to a minimal Finding representation for comparison. */
export function mapBaselineToFinding(bf: BaselineFinding): Finding {
  return {
    fingerprint: bf.fingerprint,
    ruleId: bf.ruleId,
    category: bf.category as Finding['category'],
    severity: bf.severity as Finding['severity'],
    file: bf.file,
    line: bf.line,
    message: `Baseline finding: ${bf.ruleId}`,
    confidence: 'high',
    remediation: 'Refer to original scan baseline.',
  };
}

/** Create a new Baseline object in memory. */
export function createBaseline(
  findings: Finding[],
  project: { type: string; packageManager?: string },
  advisoryInfo: AdvisoryInfo | undefined,
  toolVersion: string,
): Baseline {
  return {
    version: 1,
    createdAt: new Date().toISOString(),
    toolVersion,
    project: {
      type: project.type,
      packageManager: project.packageManager,
    },
    findings: findings.map(mapFindingToBaseline),
    advisories: {
      provider: advisoryInfo?.provider ?? 'none',
      status: advisoryInfo?.status ?? 'not_checked',
    },
  };
}

/** Write a Baseline object to the .devfoundry/baseline.json file. */
export function writeBaseline(basePath: string, baseline: Baseline): void {
  const dirPath = path.join(basePath, BASELINE_DIR);
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }

  const filePath = path.join(dirPath, BASELINE_FILE);
  fs.writeFileSync(filePath, JSON.stringify(baseline, null, 2), 'utf8');
}

/** Read the Baseline object from .devfoundry/baseline.json if it exists. */
export function readBaseline(basePath: string): Baseline | null {
  const filePath = path.join(basePath, BASELINE_DIR, BASELINE_FILE);
  if (!fs.existsSync(filePath)) {
    return null;
  }

  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(raw) as Baseline;
  } catch {
    return null;
  }
}

/**
 * Remove .devfoundry/baseline.json.
 * If the .devfoundry directory becomes empty, removes it as well.
 */
export function clearBaseline(basePath: string): boolean {
  const dirPath = path.join(basePath, BASELINE_DIR);
  const filePath = path.join(dirPath, BASELINE_FILE);

  if (!fs.existsSync(filePath)) {
    return false;
  }

  fs.unlinkSync(filePath);

  // If directory is empty, remove it
  try {
    if (fs.existsSync(dirPath)) {
      const files = fs.readdirSync(dirPath);
      if (files.length === 0) {
        fs.rmdirSync(dirPath);
      }
    }
  } catch {
    // Ignore cleanup failures
  }

  return true;
}
