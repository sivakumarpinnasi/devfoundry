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
}

export const SECRET_RULES: SecretRule[] = [
  {
    id: 'github-token',
    name: 'GitHub Token',
    pattern: /\b(ghp_[a-zA-Z0-9]{36})\b/g,
    severity: 'critical',
    confidence: 'high',
    message: 'Potential GitHub Personal Access Token detected.',
  },
  {
    id: 'aws-access-key',
    name: 'AWS Access Key ID',
    pattern: /\b(AKIA[0-9A-Z]{16})\b/g,
    severity: 'high',
    confidence: 'high',
    message: 'Potential AWS Access Key ID detected.',
  },
  {
    id: 'private-key',
    name: 'Private Key Block',
    pattern: /-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----/g,
    severity: 'critical',
    confidence: 'high',
    message: 'Private Key block detected.',
  },
  {
    id: 'db-connection-string',
    name: 'Database Connection String',
    pattern: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+(?::\d+)?\b/g,
    severity: 'critical',
    confidence: 'medium',
    message: 'Database connection string containing credentials detected.',
  },
  {
    id: 'jwt-token',
    name: 'JSON Web Token (JWT)',
    pattern: /\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b/g,
    severity: 'medium',
    confidence: 'medium',
    message: 'Potential JSON Web Token (JWT) detected.',
  },
  {
    id: 'generic-api-key',
    name: 'Generic API Key',
    pattern: /\b(?:api[_-]?key|secret[_-]?key|token|password|passwd|credential)\s*[:=]\s*['"]([a-zA-Z0-9_\-+=]{16,64})['"]/gi,
    severity: 'high',
    confidence: 'low',
    message: 'Generic API key or secret assignment detected.',
  }
];

const IGNORED_DIRS = [
  '.git',
  'node_modules',
  'dist',
  'build',
  'coverage',
];

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.gz', '.tar', '.exe',
  '.dll', '.so', '.dylib', '.woff', '.woff2', '.eot', '.ttf', '.mp3', '.mp4',
  '.wav', '.avi', '.mov', '.webp', '.dmg', '.pkg', '.class', '.jar', '.war'
]);

function shouldSkipFile(filePath: string): boolean {
  const parts = filePath.split(/[/\\]/);
  
  // Skip if file path contains ignored directory
  if (parts.some(part => IGNORED_DIRS.includes(part))) {
    return true;
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

export async function scanSecurity(context: AnalysisContext): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const file of context.files) {
    if (shouldSkipFile(file)) {
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

      for (const rule of SECRET_RULES) {
        // Reset RegExp lastIndex just in case
        rule.pattern.lastIndex = 0;

        lines.forEach((lineText: string, index: number) => {
          let match;
          // Using regex clone to prevent state sharing in loops
          const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
          
          while ((match = regex.exec(lineText)) !== null) {
            const rawValue = match[1] || match[0];
            const maskedValue = maskSecret(rawValue);
            findings.push({
              ruleId: rule.id,
              severity: rule.severity,
              message: `${rule.message} (value: ${maskedValue})`,
              file,
              line: index + 1,
              confidence: rule.confidence,
            });
          }
        });
      }
    } catch {
      // Ignore read errors
    }
  }

  return findings;
}
