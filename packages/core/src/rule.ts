/**
 * Stable rule metadata definition and registry.
 */
import type { Severity } from './index.js';

export interface RuleMetadata {
  ruleId: string;
  name: string;
  category: 'security' | 'dependencies' | 'detector';
  defaultSeverity: Severity;
  description: string;
  remediation?: string;
  documentationUrl?: string;
}

export class RuleRegistry {
  private static instance: RuleRegistry;
  private rules = new Map<string, RuleMetadata>();

  private constructor() {
    // Register default rules
    this.registerMany([
      {
        ruleId: 'github-token',
        name: 'GitHub OAuth/PAT Token',
        category: 'security',
        defaultSeverity: 'critical',
        description: 'GitHub personal access token or OAuth token detected in source code.',
        remediation: 'Revoke and rotate the token immediately.',
        documentationUrl: 'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-githubs-commitment-to-security',
      },
      {
        ruleId: 'aws-access-key',
        name: 'AWS Access Key ID',
        category: 'security',
        defaultSeverity: 'high',
        description: 'Amazon Web Services Access Key ID detected.',
        remediation: 'Deactivate the key in IAM console, check CloudTrail logs, and rotate credentials.',
        documentationUrl: 'https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html',
      },
      {
        ruleId: 'private-key',
        name: 'PEM Private Key',
        category: 'security',
        defaultSeverity: 'critical',
        description: 'Unencrypted PEM private key detected.',
        remediation: 'Revoke the certificate/key pair, issue new keys, and update key storage.',
      },
      {
        ruleId: 'database-credential',
        name: 'Database Connection String',
        category: 'security',
        defaultSeverity: 'high',
        description: 'Database connection URL with embedded username and password detected.',
        remediation: 'Move connection credentials to environment variables or secret vaults.',
      },
      {
        ruleId: 'jwt',
        name: 'JSON Web Token (JWT)',
        category: 'security',
        defaultSeverity: 'medium',
        description: 'Hardcoded JSON Web Token detected.',
        remediation: 'Revoke the token and transition to dynamic short-lived sessions.',
      },
      {
        ruleId: 'generic-api-key',
        name: 'Generic API Key',
        category: 'security',
        defaultSeverity: 'medium',
        description: 'Entropy-based high confidence generic API key pattern detected.',
        remediation: 'Identify key service provider, rotate key, and externalize configuration.',
      },
      {
        ruleId: 'dependency-vulnerability',
        name: 'Vulnerable Package Dependency',
        category: 'dependencies',
        defaultSeverity: 'high',
        description: 'One of the project dependencies has a known vulnerability registered in the OSV database.',
        remediation: 'Upgrade the package to a fixed version or apply remediation guidance.',
        documentationUrl: 'https://osv.dev',
      },
    ]);
  }

  public static getInstance(): RuleRegistry {
    if (!RuleRegistry.instance) {
      RuleRegistry.instance = new RuleRegistry();
    }
    return RuleRegistry.instance;
  }

  public register(rule: RuleMetadata): void {
    this.rules.set(rule.ruleId, rule);
  }

  public registerMany(rules: RuleMetadata[]): void {
    for (const rule of rules) {
      this.register(rule);
    }
  }

  public get(ruleId: string): RuleMetadata | undefined {
    return this.rules.get(ruleId);
  }

  public list(): RuleMetadata[] {
    return Array.from(this.rules.values());
  }
}
