// Self-validation framework for recursive MCP security scanning
import { securityAnalyzer } from './core';
import { vulnerabilityPatternDatabase } from '@/database/vulnerability-patterns';
import { 
  ScanOptions, 
  ScanResult
} from '@/types/scan';
import { 
  Vulnerability,
  VulnerabilityPattern 
} from '@/types/vulnerability';
import { 
  AnalysisType, 
  LanguageType, 
  SeverityLevel, 
  VulnerabilityType
} from '@/types';
import * as path from 'path';
import { promises as fs } from 'fs';

export class SelfValidationFramework {
  private scanHistory: ScanResult[] = [];
  private lastSelfScan?: ScanResult;

  /**
   * Perform recursive self-scan of the scanner codebase
   */
  async performSelfScan(scannerRootPath: string): Promise<SelfScanResult> {
    const startTime = new Date();
    
    // Configure self-scan options
    const scanOptions: ScanOptions = {
      analysisType: AnalysisType.HYBRID,
      targetLanguages: [LanguageType.TYPESCRIPT, LanguageType.JAVASCRIPT],
      includePaths: ['src/'],
      excludePaths: ['node_modules/', 'dist/', '.git/', 'tests/'],
      maxDepth: 10,
      timeout: 120000, // Extended timeout for self-scan
      concurrent: false,
      maxConcurrency: 1,
      enableDynamicAnalysis: false, // Disable dynamic analysis for self-scan
      enableStaticAnalysis: true,
      severityThreshold: SeverityLevel.INFO,
    };

    // Perform the scan
    const scanResult = await securityAnalyzer.scanServer(scannerRootPath, scanOptions);
    
    // Analyze self-scan results
    const analysis = await this.analyzeSelfScanResults(scanResult);
    
    // Store in history
    this.scanHistory.push(scanResult);
    this.lastSelfScan = scanResult;
    
    // Generate self-validation report
    const report = await this.generateSelfValidationReport(scanResult, analysis);

    return {
      scanResult,
      analysis,
      report,
      timestamp: startTime,
      duration: new Date().getTime() - startTime.getTime(),
      passed: analysis.securityScore >= 90, // 90% threshold for passing
    };
  }

  /**
   * Analyze self-scan results for security issues
   */
  private async analyzeSelfScanResults(scanResult: ScanResult): Promise<SelfScanAnalysis> {
    const vulnerabilities = scanResult.vulnerabilities;
    const criticalVulns = vulnerabilities.filter(v => v.severity === SeverityLevel.CRITICAL);
    const scannerSpecificIssues = this.identifyScannerSpecificIssues(vulnerabilities);
    const securityScore = this.calculateSecurityScore(vulnerabilities);
    
    return {
      totalVulnerabilities: vulnerabilities.length,
      criticalVulnerabilities: criticalVulns.length,
      scannerSpecificIssues,
      securityScore,
      recommendations: this.generateSelfScanRecommendations(vulnerabilities),
      integrityChecks: await this.performIntegrityChecks(),
      patternValidation: this.validatePatterns(),
      codeQualityMetrics: this.calculateCodeQualityMetrics(scanResult),
    };
  }

  /**
   * Identify issues specific to security scanner implementation
   */
  private identifyScannerSpecificIssues(vulnerabilities: Vulnerability[]): ScannerIssue[] {
    const issues: ScannerIssue[] = [];
    
    // Check for vulnerabilities in scanner core components
    const coreVulns = vulnerabilities.filter(v => 
      v.location.file.includes('analyzer/') || 
      v.location.file.includes('mcp-server/')
    );
    
    if (coreVulns.length > 0) {
      issues.push({
        type: 'core_vulnerability',
        severity: SeverityLevel.CRITICAL,
        description: `Found ${coreVulns.length} vulnerabilities in core scanner components`,
        affectedComponents: [...new Set(coreVulns.map(v => path.dirname(v.location.file)))],
        recommendation: 'Immediately review and fix vulnerabilities in scanner core',
      });
    }

    // Check for vulnerabilities in vulnerability detectors
    const detectorVulns = vulnerabilities.filter(v => 
      v.location.file.includes('vulnerabilities/')
    );
    
    if (detectorVulns.length > 0) {
      issues.push({
        type: 'detector_vulnerability',
        severity: SeverityLevel.HIGH,
        description: `Found ${detectorVulns.length} vulnerabilities in vulnerability detector code`,
        affectedComponents: [...new Set(detectorVulns.map(v => path.basename(v.location.file)))],
        recommendation: 'Review detector implementations for security issues',
      });
    }

    // Check for recursive vulnerabilities (scanner detecting issues in itself)
    const recursiveIssues = vulnerabilities.filter(v => 
      v.type === VulnerabilityType.COMMAND_INJECTION ||
      v.type === VulnerabilityType.PATH_TRAVERSAL
    );
    
    if (recursiveIssues.length > 0) {
      issues.push({
        type: 'recursive_vulnerability',
        severity: SeverityLevel.MEDIUM,
        description: `Scanner detected ${recursiveIssues.length} security issues in its own code`,
        affectedComponents: [...new Set(recursiveIssues.map(v => v.type))],
        recommendation: 'Apply same security standards to scanner implementation',
      });
    }

    return issues;
  }

  /**
   * Calculate overall security score for the scanner
   */
  private calculateSecurityScore(vulnerabilities: Vulnerability[]): number {
    if (vulnerabilities.length === 0) return 100;
    
    const criticalPenalty = vulnerabilities.filter(v => v.severity === SeverityLevel.CRITICAL).length * 30;
    const highPenalty = vulnerabilities.filter(v => v.severity === SeverityLevel.HIGH).length * 15;
    const mediumPenalty = vulnerabilities.filter(v => v.severity === SeverityLevel.MEDIUM).length * 5;
    const lowPenalty = vulnerabilities.filter(v => v.severity === SeverityLevel.LOW).length * 1;
    
    const totalPenalty = criticalPenalty + highPenalty + mediumPenalty + lowPenalty;
    return Math.max(0, 100 - totalPenalty);
  }

  /**
   * Generate recommendations for self-scan results
   */
  private generateSelfScanRecommendations(vulnerabilities: Vulnerability[]): string[] {
    const recommendations: string[] = [];
    
    if (vulnerabilities.length === 0) {
      recommendations.push('Scanner codebase appears secure - maintain current security practices');
      return recommendations;
    }

    const criticalCount = vulnerabilities.filter(v => v.severity === SeverityLevel.CRITICAL).length;
    if (criticalCount > 0) {
      recommendations.push(`Address ${criticalCount} critical vulnerabilities immediately`);
      recommendations.push('Review scanner security architecture');
      recommendations.push('Implement additional input validation in scanner core');
    }

    const coreVulns = vulnerabilities.filter(v => 
      v.location.file.includes('analyzer/') || v.location.file.includes('mcp-server/')
    );
    if (coreVulns.length > 0) {
      recommendations.push('Prioritize fixes in core scanner components');
      recommendations.push('Implement defense-in-depth for scanner infrastructure');
    }

    if (vulnerabilities.some(v => v.type === VulnerabilityType.COMMAND_INJECTION)) {
      recommendations.push('Review all subprocess and command execution in scanner');
    }

    if (vulnerabilities.some(v => v.type === VulnerabilityType.PATH_TRAVERSAL)) {
      recommendations.push('Audit all file system access patterns in scanner');
    }

    recommendations.push('Schedule regular self-scans to maintain security posture');
    
    return recommendations;
  }

  /**
   * Perform integrity checks on scanner components
   */
  private async performIntegrityChecks(): Promise<IntegrityCheck[]> {
    const checks: IntegrityCheck[] = [];

    // Check pattern database integrity
    try {
      const patterns = vulnerabilityPatternDatabase.getAllPatterns();
      const validPatterns = patterns.filter(p => this.validatePattern(p));
      
      checks.push({
        component: 'vulnerability_patterns',
        passed: validPatterns.length === patterns.length,
        details: `${validPatterns.length}/${patterns.length} patterns valid`,
        recommendation: validPatterns.length < patterns.length ? 'Review invalid patterns' : 'Patterns integrity verified',
      });
    } catch (error) {
      checks.push({
        component: 'vulnerability_patterns',
        passed: false,
        details: 'Pattern database access failed',
        recommendation: 'Investigate pattern database corruption',
      });
    }

    // Check for required scanner files
    const requiredFiles = [
      'src/analyzer/core.ts',
      'src/mcp-server/server.ts',
      'src/types/index.ts',
      'package.json',
    ];

    for (const file of requiredFiles) {
      try {
        await fs.access(file);
        checks.push({
          component: `file_${path.basename(file)}`,
          passed: true,
          details: 'File exists and accessible',
          recommendation: 'Continue monitoring',
        });
      } catch {
        checks.push({
          component: `file_${path.basename(file)}`,
          passed: false,
          details: 'Required file missing or inaccessible',
          recommendation: 'Restore missing file',
        });
      }
    }

    return checks;
  }

  /**
   * Validate individual vulnerability pattern
   */
  private validatePattern(pattern: VulnerabilityPattern): boolean {
    // Basic pattern validation
    if (!pattern.id || !pattern.name || !pattern.type) return false;
    if (!pattern.pattern) return false;
    if (!pattern.examples?.vulnerable || !pattern.examples?.safe) return false;
    if (pattern.examples.vulnerable.length === 0 || pattern.examples.safe.length === 0) return false;
    
    // Validate regex patterns
    if (pattern.pattern instanceof RegExp) {
      try {
        // Test the regex with sample inputs
        const testString = pattern.examples.vulnerable[0] || '';
        pattern.pattern.test(testString);
        return true;
      } catch {
        return false;
      }
    }
    
    return true;
  }

  /**
   * Validate all vulnerability patterns
   */
  private validatePatterns(): PatternValidation {
    const patterns = vulnerabilityPatternDatabase.getAllPatterns();
    const validPatterns = patterns.filter(p => this.validatePattern(p));
    const invalidPatterns = patterns.filter(p => !this.validatePattern(p));
    
    return {
      totalPatterns: patterns.length,
      validPatterns: validPatterns.length,
      invalidPatterns: invalidPatterns.length,
      validationErrors: invalidPatterns.map(p => `Pattern ${p.id}: Invalid pattern or examples`),
      coverage: this.calculatePatternCoverage(validPatterns),
    };
  }

  /**
   * Calculate pattern coverage across vulnerability types
   */
  private calculatePatternCoverage(patterns: VulnerabilityPattern[]): number {
    const supportedTypes = Object.values(VulnerabilityType);
    const coveredTypes = new Set(patterns.map(p => p.type));
    
    return coveredTypes.size / supportedTypes.length;
  }

  /**
   * Calculate code quality metrics
   */
  private calculateCodeQualityMetrics(scanResult: ScanResult): CodeQualityMetrics {
    const totalFiles = scanResult.targetInfo.totalFiles;
    const totalLines = scanResult.targetInfo.totalLines;
    const vulnerableFiles = new Set(scanResult.vulnerabilities.map(v => v.location.file)).size;
    
    return {
      totalFiles,
      totalLines,
      vulnerableFiles,
      vulnerabilityDensity: totalLines > 0 ? scanResult.vulnerabilities.length / totalLines * 1000 : 0,
      codeComplexity: scanResult.metadata.performance.filesPerSecond < 10 ? 'high' : 'normal',
      maintainabilityIndex: Math.max(0, 100 - (vulnerableFiles / totalFiles) * 100),
    };
  }

  /**
   * Generate comprehensive self-validation report
   */
  private async generateSelfValidationReport(
    scanResult: ScanResult, 
    analysis: SelfScanAnalysis
  ): Promise<string> {
    let report = `# MCP Security Scanner - Self-Validation Report\n\n`;
    report += `Generated: ${new Date().toISOString()}\n\n`;
    
    // Overall assessment
    report += `## Overall Assessment\n\n`;
    report += `**Security Score**: ${analysis.securityScore}/100\n`;
    report += `**Status**: ${analysis.securityScore >= 90 ? '✅ PASSED' : '❌ FAILED'}\n`;
    report += `**Total Vulnerabilities**: ${analysis.totalVulnerabilities}\n`;
    report += `**Critical Issues**: ${analysis.criticalVulnerabilities}\n\n`;
    
    // Scanner-specific issues
    if (analysis.scannerSpecificIssues.length > 0) {
      report += `## Scanner-Specific Security Issues\n\n`;
      analysis.scannerSpecificIssues.forEach(issue => {
        report += `### ${issue.type.toUpperCase()}\n`;
        report += `**Severity**: ${issue.severity}\n`;
        report += `**Description**: ${issue.description}\n`;
        report += `**Affected Components**: ${issue.affectedComponents.join(', ')}\n`;
        report += `**Recommendation**: ${issue.recommendation}\n\n`;
      });
    }
    
    // Integrity checks
    report += `## Integrity Checks\n\n`;
    analysis.integrityChecks.forEach(check => {
      report += `- **${check.component}**: ${check.passed ? '✅' : '❌'} ${check.details}\n`;
    });
    report += `\n`;
    
    // Pattern validation
    report += `## Pattern Validation\n\n`;
    report += `- **Total Patterns**: ${analysis.patternValidation.totalPatterns}\n`;
    report += `- **Valid Patterns**: ${analysis.patternValidation.validPatterns}\n`;
    report += `- **Pattern Coverage**: ${Math.round(analysis.patternValidation.coverage * 100)}%\n`;
    
    if (analysis.patternValidation.validationErrors.length > 0) {
      report += `\n**Pattern Errors**:\n`;
      analysis.patternValidation.validationErrors.forEach(error => {
        report += `- ${error}\n`;
      });
    }
    report += `\n`;
    
    // Code quality metrics
    report += `## Code Quality Metrics\n\n`;
    report += `- **Files Scanned**: ${analysis.codeQualityMetrics.totalFiles}\n`;
    report += `- **Lines of Code**: ${analysis.codeQualityMetrics.totalLines}\n`;
    report += `- **Vulnerable Files**: ${analysis.codeQualityMetrics.vulnerableFiles}\n`;
    report += `- **Vulnerability Density**: ${analysis.codeQualityMetrics.vulnerabilityDensity.toFixed(2)} per 1000 lines\n`;
    report += `- **Maintainability Index**: ${analysis.codeQualityMetrics.maintainabilityIndex.toFixed(1)}\n\n`;
    
    // Recommendations
    report += `## Recommendations\n\n`;
    analysis.recommendations.forEach(rec => {
      report += `- ${rec}\n`;
    });
    report += `\n`;
    
    // Historical trends (if available)
    if (this.scanHistory.length > 1) {
      report += this.generateTrendAnalysis();
    }
    
    return report;
  }

  /**
   * Generate trend analysis from historical scans
   */
  private generateTrendAnalysis(): string {
    const recent = this.scanHistory.slice(-5); // Last 5 scans
    let trend = `## Historical Trends\n\n`;
    
    // Vulnerability trend
    const vulnCounts = recent.map(scan => scan.vulnerabilities.length);
    const avgVulns = vulnCounts.reduce((sum, count) => sum + count, 0) / vulnCounts.length;
    const currentVulns = vulnCounts[vulnCounts.length - 1] || 0;
    
    const trendDirection = currentVulns > avgVulns ? 'increasing' : 'decreasing';
    trend += `**Vulnerability Trend**: ${trendDirection} (current: ${currentVulns}, average: ${avgVulns.toFixed(1)})\n`;
    
    // Risk score trend
    const riskScores = recent.map(scan => scan.summary.riskScore);
    const avgRisk = riskScores.reduce((sum, score) => sum + score, 0) / riskScores.length;
    const currentRisk = riskScores[riskScores.length - 1] || 0;
    
    const riskTrend = currentRisk < avgRisk ? 'improving' : 'declining';
    trend += `**Risk Score Trend**: ${riskTrend} (current: ${currentRisk}, average: ${avgRisk.toFixed(1)})\n\n`;
    
    return trend;
  }

  /**
   * Continuous monitoring of scanner health
   */
  async startContinuousMonitoring(
    scannerRootPath: string, 
    intervalMinutes: number = 60
  ): Promise<void> {
    const intervalMs = intervalMinutes * 60 * 1000;
    
    const monitor = async (): Promise<void> => {
      try {
        const result = await this.performSelfScan(scannerRootPath);
        
        if (!result.passed) {
          console.error('⚠️  Self-scan failed - scanner may be compromised');
          console.error(`Security score: ${result.analysis.securityScore}/100`);
        } else {
          console.log('✅ Self-scan passed - scanner integrity verified');
        }
        
        // Schedule next scan
        setTimeout(monitor, intervalMs);
        
      } catch (error) {
        console.error('Self-scan monitoring error:', error);
        // Retry after shorter interval on error
        setTimeout(monitor, intervalMs / 2);
      }
    };
    
    // Start monitoring
    console.log(`Starting continuous self-monitoring (interval: ${intervalMinutes}m)`);
    monitor();
  }

  /**
   * Validate scanner can detect known vulnerable patterns
   */
  async validateDetectionCapabilities(): Promise<DetectionValidationResult> {
    const testCases = this.generateKnownVulnerableCode();
    const results: DetectionTest[] = [];
    
    for (const testCase of testCases) {
      const tempFile = `/tmp/test_${Date.now()}_${testCase.type}.ts`;
      
      try {
        // Write test code to temporary file
        await fs.writeFile(tempFile, testCase.code);
        
        // Scan the test file
        const scanResult = await securityAnalyzer.scanServer(tempFile, {
          analysisType: AnalysisType.STATIC,
          targetLanguages: [LanguageType.TYPESCRIPT],
          includePaths: [tempFile],
          excludePaths: [],
          maxDepth: 1,
          timeout: 10000,
          concurrent: false,
          maxConcurrency: 1,
          enableDynamicAnalysis: false,
          enableStaticAnalysis: true,
          severityThreshold: SeverityLevel.INFO,
        });
        
        // Check if vulnerability was detected
        const detected = scanResult.vulnerabilities.some(v => v.type === testCase.expectedType);
        
        results.push({
          testCase: testCase.type,
          expectedType: testCase.expectedType,
          detected,
          actualDetections: scanResult.vulnerabilities.length,
          passed: detected,
        });
        
        // Cleanup
        await fs.unlink(tempFile).catch(() => {}); // Ignore cleanup errors
        
      } catch (error) {
        results.push({
          testCase: testCase.type,
          expectedType: testCase.expectedType,
          detected: false,
          actualDetections: 0,
          passed: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        });
      }
    }
    
    const passedTests = results.filter(r => r.passed).length;
    const totalTests = results.length;
    
    return {
      totalTests,
      passedTests,
      failedTests: totalTests - passedTests,
      detectionRate: totalTests > 0 ? passedTests / totalTests : 0,
      results,
      overallPassed: passedTests >= totalTests * 0.8, // 80% pass rate required
    };
  }

  /**
   * Generate known vulnerable code patterns for testing
   */
  private generateKnownVulnerableCode(): TestVulnerability[] {
    return [
      {
        type: 'command_injection_test',
        expectedType: VulnerabilityType.COMMAND_INJECTION,
        code: `
          import { exec } from 'child_process';
          function runCommand(userInput: string) {
            exec(\`ls \${userInput}\`); // Should be detected
          }
        `,
      },
      {
        type: 'path_traversal_test',
        expectedType: VulnerabilityType.PATH_TRAVERSAL,
        code: `
          import { readFileSync } from 'fs';
          function readFile(filename: string) {
            return readFileSync(\`./uploads/\${filename}\`); // Should be detected
          }
        `,
      },
      {
        type: 'eval_injection_test',
        expectedType: VulnerabilityType.COMMAND_INJECTION,
        code: `
          function evaluate(code: string) {
            return eval(\`const result = \${code}\`); // Should be detected
          }
        `,
      },
    ];
  }

  /**
   * Get last self-scan result
   */
  getLastSelfScan(): ScanResult | undefined {
    return this.lastSelfScan;
  }

  /**
   * Get scan history
   */
  getScanHistory(): ScanResult[] {
    return [...this.scanHistory];
  }

  /**
   * Clear scan history
   */
  clearHistory(): void {
    this.scanHistory = [];
    delete this.lastSelfScan;
  }
}

// Type definitions for self-validation
export interface SelfScanResult {
  scanResult: ScanResult;
  analysis: SelfScanAnalysis;
  report: string;
  timestamp: Date;
  duration: number;
  passed: boolean;
}

export interface SelfScanAnalysis {
  totalVulnerabilities: number;
  criticalVulnerabilities: number;
  scannerSpecificIssues: ScannerIssue[];
  securityScore: number;
  recommendations: string[];
  integrityChecks: IntegrityCheck[];
  patternValidation: PatternValidation;
  codeQualityMetrics: CodeQualityMetrics;
}

export interface ScannerIssue {
  type: string;
  severity: SeverityLevel;
  description: string;
  affectedComponents: string[];
  recommendation: string;
}

export interface IntegrityCheck {
  component: string;
  passed: boolean;
  details: string;
  recommendation: string;
}

export interface PatternValidation {
  totalPatterns: number;
  validPatterns: number;
  invalidPatterns: number;
  validationErrors: string[];
  coverage: number;
}

export interface CodeQualityMetrics {
  totalFiles: number;
  totalLines: number;
  vulnerableFiles: number;
  vulnerabilityDensity: number;
  codeComplexity: 'low' | 'normal' | 'high';
  maintainabilityIndex: number;
}

export interface DetectionValidationResult {
  totalTests: number;
  passedTests: number;
  failedTests: number;
  detectionRate: number;
  results: DetectionTest[];
  overallPassed: boolean;
}

export interface DetectionTest {
  testCase: string;
  expectedType: VulnerabilityType;
  detected: boolean;
  actualDetections: number;
  passed: boolean;
  error?: string;
}

export interface TestVulnerability {
  type: string;
  expectedType: VulnerabilityType;
  code: string;
}

export const selfValidationFramework = new SelfValidationFramework();
