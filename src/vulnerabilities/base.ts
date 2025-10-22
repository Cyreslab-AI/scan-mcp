// Base vulnerability detector class for extensible security analysis
import { 
  Vulnerability, 
  VulnerabilityPattern,
  VulnerabilityLocation,
  RemediationGuidance,
  CVEReference 
} from '@/types/vulnerability';
import { LanguageAST, SourceLocation } from '@/types/language';
import { LanguageType, SeverityLevel, VulnerabilityType } from '@/types';

export abstract class VulnerabilityDetector {
  protected readonly detectorType: VulnerabilityType;
  protected readonly supportedLanguages: LanguageType[];
  protected readonly patterns: VulnerabilityPattern[];

  constructor(
    type: VulnerabilityType, 
    supportedLanguages: LanguageType[],
    patterns: VulnerabilityPattern[]
  ) {
    this.detectorType = type;
    this.supportedLanguages = supportedLanguages;
    this.patterns = patterns;
  }

  /**
   * Main detection method that should be implemented by each specific detector
   */
  abstract detect(ast: LanguageAST, content: string): Promise<Vulnerability[]>;

  /**
   * Validate if this detector supports the given language
   */
  supportsLanguage(language: LanguageType): boolean {
    return this.supportedLanguages.includes(language);
  }

  /**
   * Calculate severity score based on vulnerability context
   */
  protected calculateSeverity(pattern: VulnerabilityPattern, context: DetectionContext): SeverityLevel {
    let baseSeverity = pattern.severity;

    // Increase severity based on context
    if (context.inPublicFunction) {
      baseSeverity = this.increaseSeverity(baseSeverity);
    }

    if (context.hasUserInput) {
      baseSeverity = this.increaseSeverity(baseSeverity);
    }

    if (context.inSecurityCriticalFunction) {
      baseSeverity = this.increaseSeverity(baseSeverity);
    }

    return baseSeverity;
  }

  /**
   * Increase severity level by one step
   */
  private increaseSeverity(current: SeverityLevel): SeverityLevel {
    switch (current) {
      case SeverityLevel.LOW:
        return SeverityLevel.MEDIUM;
      case SeverityLevel.MEDIUM:
        return SeverityLevel.HIGH;
      case SeverityLevel.HIGH:
        return SeverityLevel.CRITICAL;
      case SeverityLevel.CRITICAL:
        return SeverityLevel.CRITICAL; // Already at max
      default:
        return current;
    }
  }

  /**
   * Convert severity to numeric score
   */
  protected severityToScore(severity: SeverityLevel): number {
    switch (severity) {
      case SeverityLevel.CRITICAL: return 9.5;
      case SeverityLevel.HIGH: return 8.0;
      case SeverityLevel.MEDIUM: return 5.5;
      case SeverityLevel.LOW: return 2.0;
      case SeverityLevel.INFO: return 0.0;
      default: return 0.0;
    }
  }

  /**
   * Create a vulnerability object from pattern match
   */
  protected createVulnerability(
    pattern: VulnerabilityPattern,
    location: VulnerabilityLocation,
    context: DetectionContext,
    additionalData?: Record<string, unknown>
  ): Vulnerability {
    const severity = this.calculateSeverity(pattern, context);
    const score = this.severityToScore(severity);
    
    return {
      id: this.generateVulnerabilityId(),
      type: pattern.type,
      severity,
      score,
      title: pattern.name,
      description: pattern.description,
      location,
      remediation: this.generateRemediation(pattern, context),
      cveReferences: this.getCVEReferences(pattern),
      context: {
        pattern: pattern.id,
        detectionContext: context,
        ...additionalData,
      },
      detectedAt: new Date(),
      confidence: this.calculateConfidence(pattern, context),
      falsePositiveRisk: this.assessFalsePositiveRisk(pattern, context),
      tags: [pattern.type, severity, context.language],
    };
  }

  /**
   * Generate remediation guidance based on pattern and context
   */
  protected generateRemediation(pattern: VulnerabilityPattern, context: DetectionContext): RemediationGuidance {
    const baseSteps = [
      'Review the identified code section',
      'Validate all user inputs',
      'Apply appropriate sanitization',
      'Test the security fix thoroughly',
    ];

    // Add context-specific steps
    const contextSteps: string[] = [];
    
    if (context.hasUserInput) {
      contextSteps.push('Implement input validation and sanitization');
    }

    if (context.inPublicFunction) {
      contextSteps.push('Add access controls and authentication checks');
    }

    if (context.inSecurityCriticalFunction) {
      contextSteps.push('Implement additional security layers and monitoring');
    }

    return {
      title: `Fix ${pattern.name}`,
      description: `Address the ${pattern.name.toLowerCase()} vulnerability by implementing proper security controls.`,
      steps: [...baseSteps, ...contextSteps],
      references: pattern.references,
      effort: this.estimateEffort(pattern, context),
      priority: pattern.severity === SeverityLevel.CRITICAL ? 1 : 
               pattern.severity === SeverityLevel.HIGH ? 2 : 3,
    };
  }

  /**
   * Estimate effort required to fix vulnerability
   */
  private estimateEffort(pattern: VulnerabilityPattern, context: DetectionContext): 'low' | 'medium' | 'high' {
    if (pattern.severity === SeverityLevel.CRITICAL || context.inSecurityCriticalFunction) {
      return 'high';
    }

    if (pattern.severity === SeverityLevel.HIGH || context.inPublicFunction) {
      return 'medium';
    }

    return 'low';
  }

  /**
   * Calculate confidence score for detection
   */
  protected calculateConfidence(pattern: VulnerabilityPattern, context: DetectionContext): number {
    let baseConfidence = 0.7;

    // Increase confidence for clear patterns
    if (pattern.severity === SeverityLevel.CRITICAL) {
      baseConfidence += 0.2;
    }

    // Increase confidence with context
    if (context.hasUserInput) {
      baseConfidence += 0.1;
    }

    if (context.inPublicFunction) {
      baseConfidence += 0.1;
    }

    return Math.min(1.0, baseConfidence);
  }

  /**
   * Assess false positive risk
   */
  protected assessFalsePositiveRisk(pattern: VulnerabilityPattern, context: DetectionContext): 'low' | 'medium' | 'high' {
    if (pattern.severity === SeverityLevel.CRITICAL && context.hasUserInput) {
      return 'low';
    }

    if (pattern.severity === SeverityLevel.HIGH) {
      return 'medium';
    }

    return 'high';
  }

  /**
   * Get CVE references for pattern
   */
  protected getCVEReferences(pattern: VulnerabilityPattern): CVEReference[] {
    // This would typically query a CVE database
    if (pattern.cweId) {
      return [
        {
          id: `CVE-related-to-${pattern.cweId}`,
          url: `https://cwe.mitre.org/data/definitions/${pattern.cweId.split('-')[1]}.html`,
          description: `Related to ${pattern.cweId}`,
          score: this.severityToScore(pattern.severity),
        },
      ];
    }
    return [];
  }

  /**
   * Generate unique vulnerability ID
   */
  private generateVulnerabilityId(): string {
    return `vuln_${this.detectorType}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Find line and column from content position
   */
  protected findPosition(content: string, index: number): { line: number; column: number } {
    const lines = content.substring(0, index).split('\n');
    return {
      line: lines.length,
      column: lines[lines.length - 1]?.length || 0,
    };
  }

  /**
   * Extract code snippet around vulnerability
   */
  protected extractCodeSnippet(content: string, startIndex: number, endIndex: number, contextLines = 2): string {
    const lines = content.split('\n');
    const startPos = this.findPosition(content, startIndex);
    const endPos = this.findPosition(content, endIndex);
    
    const startLine = Math.max(0, startPos.line - contextLines - 1);
    const endLine = Math.min(lines.length - 1, endPos.line + contextLines - 1);
    
    return lines.slice(startLine, endLine + 1).join('\n');
  }

  /**
   * Validate detection result
   */
  protected validateDetection(vulnerability: Vulnerability): boolean {
    // Basic validation rules
    if (!vulnerability.id || !vulnerability.type || !vulnerability.severity) {
      return false;
    }

    if (vulnerability.confidence < 0 || vulnerability.confidence > 1) {
      return false;
    }

    if (vulnerability.score < 0 || vulnerability.score > 10) {
      return false;
    }

    return true;
  }

  /**
   * Get detector metadata
   */
  getMetadata(): DetectorMetadata {
    return {
      type: this.detectorType,
      supportedLanguages: this.supportedLanguages,
      patternCount: this.patterns.length,
      version: '1.0.0',
    };
  }
}

// Detection context interface
export interface DetectionContext {
  language: LanguageType;
  filePath: string;
  functionName?: string;
  className?: string;
  inPublicFunction: boolean;
  inSecurityCriticalFunction: boolean;
  hasUserInput: boolean;
  codeSnippet?: string;
  astContext?: Record<string, unknown>;
}

// Detector metadata interface
export interface DetectorMetadata {
  type: VulnerabilityType;
  supportedLanguages: LanguageType[];
  patternCount: number;
  version: string;
}

// Pattern matching utilities
export class PatternMatcher {
  /**
   * Match regex pattern in content
   */
  static matchRegex(content: string, pattern: RegExp): PatternMatch[] {
    const matches: PatternMatch[] = [];
    const allMatches = content.matchAll(pattern);

    for (const match of allMatches) {
      if (match.index !== undefined) {
        matches.push({
          match: match[0],
          index: match.index,
          length: match[0].length,
          groups: match.slice(1),
        });
      }
    }

    return matches;
  }

  /**
   * Match string pattern in content
   */
  static matchString(content: string, pattern: string, caseSensitive = false): PatternMatch[] {
    const flags = caseSensitive ? 'g' : 'gi';
    const regex = new RegExp(this.escapeRegex(pattern), flags);
    
    return this.matchRegex(content, regex);
  }

  /**
   * Escape special regex characters in string
   */
  private static escapeRegex(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
}

export interface PatternMatch {
  match: string;
  index: number;
  length: number;
  groups: string[];
}

// Security analysis utilities
export class SecurityUtils {
  /**
   * Check if function appears to be public/exported
   */
  static isPublicFunction(functionName: string, content: string): boolean {
    const exportPatterns = [
      new RegExp(`export\\s+function\\s+${functionName}`, 'i'),
      new RegExp(`export\\s+{[^}]*${functionName}[^}]*}`, 'i'),
      new RegExp(`export\\s+const\\s+${functionName}`, 'i'),
    ];

    return exportPatterns.some(pattern => pattern.test(content));
  }

  /**
   * Check if function handles user input
   */
  static hasUserInput(functionContent: string): boolean {
    const userInputPatterns = [
      /req\.(body|query|params)/i,
      /process\.argv/i,
      /stdin/i,
      /input/i,
      /user.*data/i,
      /external.*input/i,
    ];

    return userInputPatterns.some(pattern => pattern.test(functionContent));
  }

  /**
   * Check if function is security critical
   */
  static isSecurityCritical(functionName: string, functionContent: string): boolean {
    const criticalPatterns = [
      /auth/i,
      /login/i,
      /password/i,
      /secret/i,
      /token/i,
      /admin/i,
      /security/i,
      /validate/i,
      /sanitize/i,
    ];

    const nameCheck = criticalPatterns.some(pattern => pattern.test(functionName));
    const contentCheck = criticalPatterns.some(pattern => pattern.test(functionContent));

    return nameCheck || contentCheck;
  }

  /**
   * Extract function context from AST
   */
  static extractFunctionContext(_ast: LanguageAST, _position: SourceLocation): FunctionContext | undefined {
    // TODO: Implement AST traversal to find containing function
    return undefined;
  }
}

export interface FunctionContext {
  name: string;
  parameters: string[];
  isPublic: boolean;
  isAsync: boolean;
  startLine: number;
  endLine: number;
  content: string;
}
