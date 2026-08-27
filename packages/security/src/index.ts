import * as fs from 'node:fs';
import * as path from 'node:path';
import { AnalysisContext, Finding, Severity } from '@devfoundry/core';

export interface SecretRule {
  id: string;
  name: string;
  pattern: RegExp;
  severity: Severity;
  confidence: 'low' | 'medium' | 'high';
  message: string;
  remediation: string;
  isGeneric?: boolean;
}

export const SECRET_RULES: SecretRule[] = [
  {
    id: 'github-token',
    name: 'GitHub Token',
    pattern: /\b(ghp_[a-zA-Z0-9]{36})\b/g,
    severity: 'critical',
    confidence: 'high',
    message: 'Potential GitHub Personal Access Token detected.',
    remediation: 'Revoke the token immediately and remove it from source history.',
  },
  {
    id: 'aws-access-key',
    name: 'AWS Access Key ID',
    pattern: /\b(AKIA[0-9A-Z]{16})\b/g,
    severity: 'high',
    confidence: 'high',
    message: 'Potential AWS Access Key ID detected.',
    remediation: 'Rotate the AWS credentials immediately and remove them from repository source.',
  },
  {
    id: 'private-key',
    name: 'Private Key Block',
    pattern: /-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----/g,
    severity: 'critical',
    confidence: 'high',
    message: 'Private Key block detected.',
    remediation: 'Revoke the key immediately, remove it from git history, and use environment variables or a secret store.',
  },
  {
    id: 'database-credential',
    name: 'Database Connection String',
    pattern: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+(?::\d+)?\b/g,
    severity: 'critical',
    confidence: 'medium',
    message: 'Database connection string containing credentials detected.',
    remediation: 'Move connection credentials to configuration/environment files and do not commit them.',
  },
  {
    id: 'jwt',
    name: 'JSON Web Token (JWT)',
    pattern: /\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b/g,
    severity: 'medium',
    confidence: 'medium',
    message: 'Potential JSON Web Token (JWT) detected.',
    remediation: 'Invalidate the token immediately and ensure keys/secrets are never hardcoded.',
  },
  {
    id: 'generic-api-key',
    name: 'Generic API Key',
    pattern: /\b(?:api[_-]?key|secret[_-]?key|token|password|passwd|credential)\s*[:=]\s*['"]([a-zA-Z0-9_\-+=]{16,64})['"]/gi,
    severity: 'high',
    confidence: 'low',
    message: 'Generic API key or secret assignment detected.',
    remediation: 'Use configuration profiles or environment variables rather than hardcoding secrets.',
    isGeneric: true,
  }
];

const IGNORED_DIRS = ['.git', 'node_modules', 'dist', 'build', 'coverage'];
const TEST_DIRS = ['tests', 'test', '__tests__', 'fixtures', '__fixtures__'];

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.gz', '.tar', '.exe',
  '.dll', '.so', '.dylib', '.woff', '.woff2', '.eot', '.ttf', '.mp3', '.mp4',
  '.wav', '.avi', '.mov', '.webp', '.dmg', '.pkg', '.class', '.jar', '.war'
]);

function shouldSkipFile(filePath: string, strict: boolean, basePath?: string): boolean {
  const parts = filePath.split(/[/\\]/);
  
  // Skip if file path contains ignored directory
  if (parts.some(part => IGNORED_DIRS.includes(part))) {
    return true;
  }

  // Skip test/fixture directories in non-strict mode
  if (!strict && parts.some(part => TEST_DIRS.includes(part))) {
    return true;
  }

  if (basePath) {
    const fullPath = path.isAbsolute(filePath) ? filePath : path.join(basePath, filePath);
    const fullParts = fullPath.split(/[/\\]/);
    if (fullParts.some(part => IGNORED_DIRS.includes(part))) {
      return true;
    }
    if (!strict && fullParts.some(part => TEST_DIRS.includes(part))) {
      return true;
    }
  }

  // Skip binary extensions
  const ext = path.extname(filePath).toLowerCase();
  if (BINARY_EXTENSIONS.has(ext)) {
    return true;
  }

  return false;
}

export function maskSecret(secret: string): string {
  if (secret.length <= 8) {
    return '********';
  }
  return secret.slice(0, 4) + '...' + secret.slice(-4);
}

interface MatchSpan {
  start: number;
  end: number;
}

export async function scanSecurity(context: AnalysisContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  const strict = !!context.strict;

  for (const file of context.files) {
    if (shouldSkipFile(file, strict, context.basePath)) {
      continue;
    }

    const fullPath = path.isAbsolute(file) ? file : path.join(context.basePath, file);
    if (!fs.existsSync(fullPath)) {
      continue;
    }

    try {
      const stats = fs.statSync(fullPath);
      if (stats.isDirectory()) {
        continue;
      }
      
      const content = fs.readFileSync(fullPath, 'utf8');
      const lines = content.split(/\r?\n/);

      // We maintain matched spans per line to perform deduplication
      const lineSpans: Map<number, MatchSpan[]> = new Map();

      // Separate specific rules and generic rules
      const specificRules = SECRET_RULES.filter(r => !r.isGeneric);
      const genericRules = SECRET_RULES.filter(r => r.isGeneric);

      const runRule = (rule: SecretRule, isGenericCheck: boolean) => {
        rule.pattern.lastIndex = 0;
        
        lines.forEach((lineText: string, index: number) => {
          const lineNum = index + 1;
          let match;
          const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
          
          while ((match = regex.exec(lineText)) !== null) {
            const matchStart = match.index;
            const matchEnd = match.index + match[0].length;

            if (isGenericCheck) {
              const spans = lineSpans.get(lineNum) || [];
              const hasOverlap = spans.some(span => !(matchEnd <= span.start || matchStart >= span.end));
              if (hasOverlap) {
                continue; // Skip generic match since it overlaps with a specific match
              }
            }

            // Record matched span
            const spans = lineSpans.get(lineNum) || [];
            spans.push({ start: matchStart, end: matchEnd });
            lineSpans.set(lineNum, spans);

            const rawValue = match[1] || match[0];
            const maskedValue = maskSecret(rawValue);
            const message = `${rule.message} (value: ${maskedValue})`;
            
            // Stable fingerprint
            const rawFingerprint = `${rule.id}:${file}:${lineNum}:${maskedValue}`;
            const fingerprint = Buffer.from(rawFingerprint).toString('base64');

            findings.push({
              ruleId: rule.id,
              category: 'security',
              severity: rule.severity,
              message,
              file,
              line: lineNum,
              confidence: rule.confidence,
              fingerprint,
              remediation: rule.remediation,
            });
          }
        });
      };

      // Run specific rules first
      specificRules.forEach(rule => runRule(rule, false));

      // Run generic rules next with overlap check enabled
      genericRules.forEach(rule => runRule(rule, true));

    } catch {
      // Ignore read errors
    }
  }

  return findings;
}
