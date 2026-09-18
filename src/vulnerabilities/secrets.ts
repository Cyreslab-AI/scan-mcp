// Secrets scanning - gitleaks/trufflehog-style regex + Shannon-entropy detection of hardcoded
// credentials. This did not previously exist anywhere in the codebase.
import { Vulnerability, RemediationGuidance } from '@/types/vulnerability';
import { SeverityLevel, VulnerabilityType } from '@/types';

interface SecretRule {
  id: string;
  name: string;
  pattern: RegExp;
  severity: SeverityLevel;
  // Index of the capture group holding the actual secret value to redact in the report.
  // Defaults to the whole match (0) when not specified.
  secretGroup?: number;
}

const PLACEHOLDER_RE = /^(x+|0+|1+|dummy|example|sample|changeme|change_me|placeholder|redacted|your[-_]?api[-_]?key|your[-_]?token|<.*>|\{\{.*\}\}|\$\{.*\}|process\.env|xxxx+)$/i;

const RULES: SecretRule[] = [
  {
    id: 'secret_aws_access_key',
    name: 'AWS Access Key ID',
    pattern: /\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b/g,
    severity: SeverityLevel.CRITICAL,
  },
  {
    id: 'secret_aws_secret_key',
    name: 'AWS Secret Access Key',
    pattern: /aws_secret_access_key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    severity: SeverityLevel.CRITICAL,
    secretGroup: 1,
  },
  {
    id: 'secret_github_token',
    name: 'GitHub Token',
    pattern: /\b(gh[pousr]_[A-Za-z0-9]{36,255})\b/g,
    severity: SeverityLevel.CRITICAL,
  },
  {
    id: 'secret_slack_token',
    name: 'Slack Token',
    pattern: /\b(xox[baprs]-[A-Za-z0-9-]{10,72})\b/g,
    severity: SeverityLevel.CRITICAL,
  },
  {
    id: 'secret_slack_webhook',
    name: 'Slack Webhook URL',
    pattern: /(https:\/\/hooks\.slack\.com\/services\/T[0-9A-Za-z]+\/B[0-9A-Za-z]+\/[0-9A-Za-z]+)/g,
    severity: SeverityLevel.HIGH,
  },
  {
    id: 'secret_google_api_key',
    name: 'Google API Key',
    pattern: /\b(AIza[0-9A-Za-z\-_]{35})\b/g,
    severity: SeverityLevel.CRITICAL,
  },
  {
    id: 'secret_stripe_key',
    name: 'Stripe API Key',
    pattern: /\b(sk_(?:live|test)_[0-9a-zA-Z]{16,247})\b/g,
    severity: SeverityLevel.CRITICAL,
  },
  {
    id: 'secret_private_key_header',
    name: 'Private Key Material',
    pattern: /(-----BEGIN\s?(?:RSA|EC|DSA|OPENSSH|PGP)?\s?PRIVATE KEY-----)/g,
    severity: SeverityLevel.CRITICAL,
  },
  {
    id: 'secret_generic_api_key_assignment',
    name: 'Hardcoded API key / secret assignment',
    pattern: /\b(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password)\b\s*[:=]\s*['"]([A-Za-z0-9_\-/+=.]{12,})['"]/gi,
    severity: SeverityLevel.HIGH,
    secretGroup: 1,
  },
];

function shannonEntropy(value: string): number {
  const freq = new Map<string, number>();
  for (const ch of value) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Generic `<name-that-looks-secret-ish> = "<opaque value>"` assignments (JS/TS/Python/JSON-ish),
// scored by entropy since there's no fixed known prefix to match against.
const ENTROPY_ASSIGNMENT_RE = /\b([A-Za-z_][A-Za-z0-9_]{2,40}(?:secret|token|key|password|credential)[A-Za-z0-9_]{0,10})\b\s*[:=]\s*['"]([A-Za-z0-9+/_\-.]{20,200})['"]/gi;

function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_RE.test(value.trim());
}

function redact(value: string): string {
  if (value.length <= 8) return '*'.repeat(value.length);
  return `${value.slice(0, 4)}${'*'.repeat(Math.max(4, value.length - 8))}${value.slice(-4)}`;
}

function findPosition(content: string, index: number): { line: number; column: number } {
  const lines = content.substring(0, index).split('\n');
  return { line: lines.length, column: lines[lines.length - 1]?.length || 0 };
}

function remediation(secretKind: string): RemediationGuidance {
  return {
    title: `Remove hardcoded ${secretKind}`,
    description: 'Hardcoded credentials in source control are readable by anyone with repository access and remain in history even after deletion.',
    steps: [
      'Revoke/rotate the exposed credential immediately',
      'Move it to an environment variable, secret manager, or .env file excluded from version control',
      'Purge it from git history if it was ever committed (e.g. git filter-repo / BFG Repo-Cleaner)',
    ],
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
    ],
    effort: 'medium',
    priority: 1,
  };
}

function severityToScore(severity: SeverityLevel): number {
  switch (severity) {
    case SeverityLevel.CRITICAL: return 9.5;
    case SeverityLevel.HIGH: return 8.0;
    case SeverityLevel.MEDIUM: return 5.5;
    case SeverityLevel.LOW: return 2.0;
    case SeverityLevel.INFO: return 0.0;
    default: return 0.0;
  }
}

function makeVulnerability(
  filePath: string,
  content: string,
  index: number,
  ruleId: string,
  name: string,
  severity: SeverityLevel,
  confidence: number,
  redactedSecret: string
): Vulnerability {
  const position = findPosition(content, index);
  return {
    id: `secret_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    type: VulnerabilityType.HARDCODED_SECRET,
    severity,
    score: severityToScore(severity),
    title: `Hardcoded secret detected: ${name}`,
    description: `A value matching the pattern for "${name}" was found hardcoded in source (redacted: ${redactedSecret}).`,
    location: { file: filePath, line: position.line, column: position.column },
    remediation: remediation(name),
    cveReferences: [],
    context: { rule: ruleId, detectionMethod: 'regex+entropy' },
    detectedAt: new Date(),
    confidence,
    falsePositiveRisk: severity === SeverityLevel.CRITICAL ? 'low' : 'medium',
    tags: [VulnerabilityType.HARDCODED_SECRET, severity, ruleId],
  };
}

/**
 * Scan a file's raw content for hardcoded credentials using known secret formats (regex) and a
 * generic, entropy-based fallback for opaque values assigned to secret-looking variable names.
 */
export function detectSecrets(content: string, filePath: string): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];
  // Absolute [start, end) ranges of secret *values* already reported by a specific-format rule,
  // so the generic entropy fallback below doesn't re-report the exact same credential at a lower
  // (and less informative) severity.
  const coveredRanges: Array<[number, number]> = [];

  for (const rule of RULES) {
    const regex = new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : `${rule.pattern.flags}g`);
    for (const match of content.matchAll(regex)) {
      if (match.index === undefined) continue;
      const secretValue = match[rule.secretGroup ?? 0] ?? match[0];
      if (!secretValue || isPlaceholder(secretValue)) continue;

      const valueStart = match.index + match[0].indexOf(secretValue);
      coveredRanges.push([valueStart, valueStart + secretValue.length]);

      vulnerabilities.push(makeVulnerability(
        filePath,
        content,
        match.index,
        rule.id,
        rule.name,
        rule.severity,
        0.85,
        redact(secretValue)
      ));
    }
  }

  for (const match of content.matchAll(ENTROPY_ASSIGNMENT_RE)) {
    if (match.index === undefined) continue;
    const varName = match[1];
    const value = match[2];
    if (!varName || !value || isPlaceholder(value)) continue;

    const valueStart = match.index + match[0].indexOf(value);
    const valueEnd = valueStart + value.length;
    const alreadyCovered = coveredRanges.some(([start, end]) => valueStart < end && valueEnd > start);
    if (alreadyCovered) continue;

    const entropy = shannonEntropy(value);
    if (entropy < 3.5) continue; // Low entropy -> likely not a real secret (e.g. a sentence or path).

    vulnerabilities.push(makeVulnerability(
      filePath,
      content,
      match.index,
      'secret_high_entropy_assignment',
      `High-entropy value assigned to "${varName}"`,
      SeverityLevel.MEDIUM,
      0.5,
      redact(value)
    ));
  }

  return vulnerabilities;
}
