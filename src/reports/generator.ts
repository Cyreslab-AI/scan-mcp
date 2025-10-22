// Flexible report generation system for security scan results
import { promises as fs } from 'fs';
import * as path from 'path';
import { 
  VulnerabilityReport, 
  ReportOptions, 
  ReportSummary,
  SarifReport,
  HtmlReportData,
  ReportExporter 
} from '@/types/report';
import { ScanResult, ScanSummary } from '@/types/scan';
import { Vulnerability } from '@/types/vulnerability';
import { ReportFormat, SeverityLevel } from '@/types';

export class SecurityReportGenerator {
  private exporters: Map<ReportFormat, ReportExporter> = new Map();

  constructor() {
    this.initializeExporters();
  }

  private initializeExporters(): void {
    this.exporters.set(ReportFormat.JSON, new JsonReportExporter());
    this.exporters.set(ReportFormat.SARIF, new SarifReportExporter());
    this.exporters.set(ReportFormat.HTML, new HtmlReportExporter());
    this.exporters.set(ReportFormat.MARKDOWN, new MarkdownReportExporter());
    this.exporters.set(ReportFormat.CSV, new CsvReportExporter());
  }

  /**
   * Generate security report from scan results
   */
  async generateReport(
    scanResult: ScanResult, 
    options: ReportOptions
  ): Promise<VulnerabilityReport> {
    // Filter vulnerabilities based on minimum severity
    const filteredVulns = scanResult.vulnerabilities.filter(vuln => 
      this.severityToNumber(vuln.severity) >= this.severityToNumber(options.minSeverity)
    );

    // Create enhanced summary
    const enhancedSummary = this.createEnhancedSummary(scanResult.summary, filteredVulns);

    // Build report
    const report: VulnerabilityReport = {
      id: this.generateReportId(),
      scanResult,
      options,
      summary: enhancedSummary,
      sections: this.generateReportSections(scanResult, filteredVulns, options),
      generatedAt: new Date(),
      version: '1.0.0',
    };

    return report;
  }

  /**
   * Export report to specified format
   */
  async exportReport(
    report: VulnerabilityReport, 
    format: ReportFormat = ReportFormat.JSON
  ): Promise<string> {
    const exporter = this.exporters.get(format);
    if (!exporter) {
      throw new Error(`Unsupported report format: ${format}`);
    }

    return await exporter.export(report, report.options);
  }

  /**
   * Save report to file
   */
  async saveReport(
    report: VulnerabilityReport,
    filePath: string,
    format?: ReportFormat
  ): Promise<void> {
    const detectedFormat = format || this.detectFormatFromPath(filePath);
    const content = await this.exportReport(report, detectedFormat);
    
    // Ensure directory exists
    const dir = path.dirname(filePath);
    await fs.mkdir(dir, { recursive: true });
    
    // Write report
    await fs.writeFile(filePath, content, 'utf-8');
  }

  /**
   * Generate multiple report formats
   */
  async generateMultipleReports(
    scanResult: ScanResult,
    outputDir: string,
    formats: ReportFormat[] = [ReportFormat.JSON, ReportFormat.HTML, ReportFormat.MARKDOWN]
  ): Promise<string[]> {
    const generatedFiles: string[] = [];

    for (const format of formats) {
      const options: ReportOptions = {
        format,
        outputPath: outputDir,
        includeDetails: true,
        includeExploitProofs: true,
        includeRemediation: true,
        includeCVEReferences: true,
        includeCodeSnippets: true,
        minSeverity: SeverityLevel.LOW,
      };

      const report = await this.generateReport(scanResult, options);
      const fileName = `security-report-${Date.now()}.${this.getFileExtension(format)}`;
      const filePath = path.join(outputDir, fileName);
      
      await this.saveReport(report, filePath, format);
      generatedFiles.push(filePath);
    }

    return generatedFiles;
  }

  private createEnhancedSummary(baseSummary: ScanSummary, vulnerabilities: Vulnerability[]): ReportSummary {
    return {
      ...baseSummary,
      executiveSummary: this.generateExecutiveSummary(vulnerabilities),
      keyFindings: this.extractKeyFindings(vulnerabilities),
      riskAssessment: {
        overallRisk: this.calculateOverallRisk(vulnerabilities),
        businessImpact: this.assessBusinessImpact(vulnerabilities),
        exploitability: this.calculateExploitability(vulnerabilities),
        attackSurface: this.calculateAttackSurface(vulnerabilities),
        dataAtRisk: this.identifyDataAtRisk(vulnerabilities),
        mitigationPriority: this.prioritizeMitigation(vulnerabilities),
      },
      complianceStatus: {
        frameworks: [],
        overallScore: this.calculateComplianceScore(vulnerabilities),
        gaps: [],
        certifications: [],
      },
    };
  }

  private generateExecutiveSummary(vulnerabilities: Vulnerability[]): string {
    const criticalCount = vulnerabilities.filter(v => v.severity === SeverityLevel.CRITICAL).length;
    const highCount = vulnerabilities.filter(v => v.severity === SeverityLevel.HIGH).length;
    
    let summary = `Security analysis identified ${vulnerabilities.length} vulnerabilities`;
    
    if (criticalCount > 0) {
      summary += `, including ${criticalCount} critical security issues that require immediate attention`;
    }
    
    if (highCount > 0) {
      summary += ` and ${highCount} high-severity issues`;
    }
    
    summary += '. The most significant risks involve';
    
    const riskTypes = this.getTopRiskTypes(vulnerabilities);
    summary += ` ${riskTypes.join(', ')}.`;
    
    return summary;
  }

  private extractKeyFindings(vulnerabilities: Vulnerability[]): string[] {
    return vulnerabilities
      .filter(v => v.severity === SeverityLevel.CRITICAL || v.severity === SeverityLevel.HIGH)
      .slice(0, 5)
      .map(v => `${v.title} in ${path.basename(v.location.file)}:${v.location.line}`);
  }

  private calculateOverallRisk(vulnerabilities: Vulnerability[]): SeverityLevel {
    if (vulnerabilities.some(v => v.severity === SeverityLevel.CRITICAL)) {
      return SeverityLevel.CRITICAL;
    }
    if (vulnerabilities.some(v => v.severity === SeverityLevel.HIGH)) {
      return SeverityLevel.HIGH;
    }
    if (vulnerabilities.some(v => v.severity === SeverityLevel.MEDIUM)) {
      return SeverityLevel.MEDIUM;
    }
    return SeverityLevel.LOW;
  }

  private assessBusinessImpact(vulnerabilities: Vulnerability[]): 'low' | 'medium' | 'high' | 'critical' {
    const criticalVulns = vulnerabilities.filter(v => v.severity === SeverityLevel.CRITICAL).length;
    const highVulns = vulnerabilities.filter(v => v.severity === SeverityLevel.HIGH).length;
    
    if (criticalVulns > 0) return 'critical';
    if (highVulns >= 3) return 'high';
    if (highVulns > 0) return 'medium';
    return 'low';
  }

  private calculateExploitability(vulnerabilities: Vulnerability[]): number {
    if (vulnerabilities.length === 0) return 0;
    
    const avgConfidence = vulnerabilities.reduce((sum, v) => sum + v.confidence, 0) / vulnerabilities.length;
    const criticalWeight = vulnerabilities.filter(v => v.severity === SeverityLevel.CRITICAL).length / vulnerabilities.length;
    
    return Math.min(1.0, avgConfidence + criticalWeight * 0.3);
  }

  private calculateAttackSurface(vulnerabilities: Vulnerability[]): number {
    const files = new Set(vulnerabilities.map(v => v.location.file));
    const functions = new Set(vulnerabilities.map(v => v.location.function).filter(Boolean));
    
    // Normalized attack surface metric
    return Math.min(1.0, (files.size * 0.1 + functions.size * 0.05) / 10);
  }

  private identifyDataAtRisk(vulnerabilities: Vulnerability[]): string[] {
    const dataTypes = new Set<string>();
    
    vulnerabilities.forEach(vuln => {
      if (vuln.type === 'path_traversal') {
        dataTypes.add('File system data');
      }
      if (vuln.type === 'command_injection') {
        dataTypes.add('System access');
      }
      if (vuln.type === 'prompt_injection') {
        dataTypes.add('AI model behavior');
      }
      if (vuln.type === 'data_exfiltration') {
        dataTypes.add('Sensitive information');
      }
    });
    
    return Array.from(dataTypes);
  }

  private prioritizeMitigation(vulnerabilities: Vulnerability[]): any[] {
    return vulnerabilities
      .sort((a, b) => b.score - a.score)
      .slice(0, 10)
      .map(vuln => ({
        vulnerability: vuln.title,
        priority: vuln.remediation.priority,
        effort: vuln.remediation.effort,
        impact: this.severityToImpact(vuln.severity),
        timeline: this.estimateTimeline(vuln),
        resources: ['Security team', 'Development team'],
      }));
  }

  private calculateComplianceScore(vulnerabilities: Vulnerability[]): number {
    const totalIssues = vulnerabilities.length;
    const criticalIssues = vulnerabilities.filter(v => v.severity === SeverityLevel.CRITICAL).length;
    const highIssues = vulnerabilities.filter(v => v.severity === SeverityLevel.HIGH).length;
    
    if (totalIssues === 0) return 100;
    
    const penalty = (criticalIssues * 30) + (highIssues * 15) + (totalIssues * 2);
    return Math.max(0, 100 - penalty);
  }

  private generateReportSections(
    scanResult: ScanResult,
    vulnerabilities: Vulnerability[],
    options: ReportOptions
  ): any[] {
    const sections = [];
    
    // Executive summary section
    sections.push({
      id: 'executive-summary',
      title: 'Executive Summary',
      content: this.generateExecutiveSummary(vulnerabilities),
      order: 1,
      enabled: true,
    });
    
    // Vulnerability details section
    if (options.includeDetails) {
      sections.push({
        id: 'vulnerability-details',
        title: 'Vulnerability Details',
        content: vulnerabilities.map(v => this.formatVulnerabilityDetail(v, options)).join('\n\n'),
        order: 2,
        enabled: true,
      });
    }
    
    // Recommendations section
    sections.push({
      id: 'recommendations',
      title: 'Security Recommendations',
      content: scanResult.summary.recommendedActions.join('\n'),
      order: 3,
      enabled: true,
    });
    
    return sections;
  }

  private formatVulnerabilityDetail(vuln: Vulnerability, options: ReportOptions): string {
    let detail = `## ${vuln.title}\n`;
    detail += `**Severity**: ${vuln.severity.toUpperCase()}\n`;
    detail += `**Location**: ${vuln.location.file}:${vuln.location.line}\n`;
    detail += `**Description**: ${vuln.description}\n`;
    
    if (options.includeRemediation) {
      detail += `\n**Remediation**:\n${vuln.remediation.steps.map(step => `- ${step}`).join('\n')}\n`;
    }
    
    if (options.includeCVEReferences && vuln.cveReferences.length > 0) {
      detail += `\n**Related CVEs**:\n${vuln.cveReferences.map(cve => `- ${cve.id}: ${cve.description}`).join('\n')}\n`;
    }
    
    return detail;
  }

  private getTopRiskTypes(vulnerabilities: Vulnerability[]): string[] {
    const typeCounts = new Map<string, number>();
    
    vulnerabilities.forEach(vuln => {
      const current = typeCounts.get(vuln.type) || 0;
      typeCounts.set(vuln.type, current + 1);
    });
    
    return Array.from(typeCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([type]) => type.replace('_', ' '));
  }

  private severityToNumber(severity: SeverityLevel): number {
    switch (severity) {
      case SeverityLevel.CRITICAL: return 4;
      case SeverityLevel.HIGH: return 3;
      case SeverityLevel.MEDIUM: return 2;
      case SeverityLevel.LOW: return 1;
      case SeverityLevel.INFO: return 0;
      default: return 0;
    }
  }

  private severityToImpact(severity: SeverityLevel): 'low' | 'medium' | 'high' {
    switch (severity) {
      case SeverityLevel.CRITICAL:
      case SeverityLevel.HIGH:
        return 'high';
      case SeverityLevel.MEDIUM:
        return 'medium';
      default:
        return 'low';
    }
  }

  private estimateTimeline(vuln: Vulnerability): string {
    switch (vuln.severity) {
      case SeverityLevel.CRITICAL: return 'Immediate (24-48 hours)';
      case SeverityLevel.HIGH: return 'Urgent (1-2 weeks)';
      case SeverityLevel.MEDIUM: return 'Standard (2-4 weeks)';
      default: return 'Low priority (1-3 months)';
    }
  }

  private detectFormatFromPath(filePath: string): ReportFormat {
    const ext = path.extname(filePath).toLowerCase();
    
    switch (ext) {
      case '.json': return ReportFormat.JSON;
      case '.html': return ReportFormat.HTML;
      case '.md': return ReportFormat.MARKDOWN;
      case '.csv': return ReportFormat.CSV;
      case '.sarif': return ReportFormat.SARIF;
      default: return ReportFormat.JSON;
    }
  }

  private getFileExtension(format: ReportFormat): string {
    switch (format) {
      case ReportFormat.JSON: return 'json';
      case ReportFormat.HTML: return 'html';
      case ReportFormat.MARKDOWN: return 'md';
      case ReportFormat.CSV: return 'csv';
      case ReportFormat.SARIF: return 'sarif';
      default: return 'txt';
    }
  }

  private generateReportId(): string {
    return `report_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

// JSON Report Exporter
class JsonReportExporter implements ReportExporter {
  format = ReportFormat.JSON;

  async export(report: VulnerabilityReport, _options: ReportOptions): Promise<string> {
    return JSON.stringify(report, null, 2);
  }

  validate(report: VulnerabilityReport): boolean {
    return report && report.scanResult && Array.isArray(report.scanResult.vulnerabilities);
  }
}

// SARIF Report Exporter
class SarifReportExporter implements ReportExporter {
  format = ReportFormat.SARIF;

  async export(report: VulnerabilityReport, _options: ReportOptions): Promise<string> {
    const sarifReport: SarifReport = {
      version: '2.1.0',
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      runs: [
        {
          tool: {
            driver: {
              name: 'MCP Security Scanner',
              version: '1.0.0',
              informationUri: 'https://github.com/cyreslab/mcp-security-scanner',
              rules: this.generateSarifRules(report.scanResult.vulnerabilities),
            },
          },
          results: this.generateSarifResults(report.scanResult.vulnerabilities),
        },
      ],
    };

    return JSON.stringify(sarifReport, null, 2);
  }

  validate(report: VulnerabilityReport): boolean {
    return report && report.scanResult && Array.isArray(report.scanResult.vulnerabilities);
  }

  private generateSarifRules(vulnerabilities: Vulnerability[]): any[] {
    const uniqueTypes = [...new Set(vulnerabilities.map(v => v.type))];
    
    return uniqueTypes.map(type => ({
      id: type,
      name: type.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase()),
      shortDescription: { text: `${type.replace('_', ' ')} vulnerability` },
      fullDescription: { text: `Detects ${type.replace('_', ' ')} vulnerabilities` },
      defaultConfiguration: { level: 'error' },
    }));
  }

  private generateSarifResults(vulnerabilities: Vulnerability[]): any[] {
    return vulnerabilities.map(vuln => ({
      ruleId: vuln.type,
      message: { text: vuln.description },
      level: this.severityToSarifLevel(vuln.severity),
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: vuln.location.file },
            region: {
              startLine: vuln.location.line,
              startColumn: vuln.location.column,
            },
          },
        },
      ],
    }));
  }

  private severityToSarifLevel(severity: SeverityLevel): 'error' | 'warning' | 'note' {
    switch (severity) {
      case SeverityLevel.CRITICAL:
      case SeverityLevel.HIGH:
        return 'error';
      case SeverityLevel.MEDIUM:
        return 'warning';
      default:
        return 'note';
    }
  }
}

// HTML Report Exporter
class HtmlReportExporter implements ReportExporter {
  format = ReportFormat.HTML;

  async export(report: VulnerabilityReport, options: ReportOptions): Promise<string> {
    const data: HtmlReportData = {
      title: 'MCP Security Scan Report',
      subtitle: `Generated on ${report.generatedAt.toLocaleDateString()}`,
      summary: report.summary,
      vulnerabilities: report.scanResult.vulnerabilities,
      charts: this.generateChartData(report.scanResult.vulnerabilities),
      metadata: {
        generatedAt: report.generatedAt,
        scannerVersion: '1.0.0',
        reportVersion: '1.0.0',
        theme: 'light',
        interactive: true,
        totalSize: 0,
      },
    };

    return this.generateHtmlTemplate(data);
  }

  validate(report: VulnerabilityReport): boolean {
    return report && report.scanResult && Array.isArray(report.scanResult.vulnerabilities);
  }

  private generateChartData(vulnerabilities: Vulnerability[]): any[] {
    return [
      {
        type: 'pie',
        title: 'Vulnerabilities by Severity',
        data: this.getSeverityDistribution(vulnerabilities),
      },
      {
        type: 'bar',
        title: 'Vulnerabilities by Type',
        data: this.getTypeDistribution(vulnerabilities),
      },
    ];
  }

  private getSeverityDistribution(vulnerabilities: Vulnerability[]): any[] {
    const distribution = new Map<string, number>();
    
    vulnerabilities.forEach(vuln => {
      const current = distribution.get(vuln.severity) || 0;
      distribution.set(vuln.severity, current + 1);
    });
    
    return Array.from(distribution.entries()).map(([severity, count]) => ({
      label: severity.toUpperCase(),
      value: count,
      color: this.getSeverityColor(severity as SeverityLevel),
    }));
  }

  private getTypeDistribution(vulnerabilities: Vulnerability[]): any[] {
    const distribution = new Map<string, number>();
    
    vulnerabilities.forEach(vuln => {
      const current = distribution.get(vuln.type) || 0;
      distribution.set(vuln.type, current + 1);
    });
    
    return Array.from(distribution.entries()).map(([type, count]) => ({
      label: type.replace('_', ' ').toUpperCase(),
      value: count,
    }));
  }

  private getSeverityColor(severity: SeverityLevel): string {
    switch (severity) {
      case SeverityLevel.CRITICAL: return '#dc3545';
      case SeverityLevel.HIGH: return '#fd7e14';
      case SeverityLevel.MEDIUM: return '#ffc107';
      case SeverityLevel.LOW: return '#20c997';
      case SeverityLevel.INFO: return '#6c757d';
      default: return '#6c757d';
    }
  }

  private generateHtmlTemplate(data: HtmlReportData): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${data.title}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; }
        .header { text-align: center; margin-bottom: 40px; }
        .summary { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; }
        .vulnerability { border-left: 4px solid #dc3545; padding: 15px; margin: 15px 0; background: #fff; }
        .critical { border-left-color: #dc3545; }
        .high { border-left-color: #fd7e14; }
        .medium { border-left-color: #ffc107; }
        .low { border-left-color: #20c997; }
        .severity { font-weight: bold; text-transform: uppercase; }
        .location { font-family: monospace; background: #f8f9fa; padding: 2px 6px; border-radius: 3px; }
        .chart { margin: 20px 0; }
        .footer { margin-top: 40px; text-align: center; color: #6c757d; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>${data.title}</h1>
        <p>${data.subtitle}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Vulnerabilities:</strong> ${data.summary.totalVulnerabilities}</p>
        <p><strong>Risk Score:</strong> ${data.summary.riskScore}/100</p>
        <p><strong>Confidence:</strong> ${Math.round(data.summary.confidence * 100)}%</p>
    </div>
    
    <div class="vulnerabilities">
        <h2>Vulnerabilities</h2>
        ${data.vulnerabilities.slice(0, 20).map(vuln => `
            <div class="vulnerability ${vuln.severity}">
                <h3>${vuln.title}</h3>
                <p><span class="severity">${vuln.severity}</span> - 
                <span class="location">${path.basename(vuln.location.file)}:${vuln.location.line}</span></p>
                <p>${vuln.description}</p>
            </div>
        `).join('')}
    </div>
    
    <div class="footer">
        <p>Generated by MCP Security Scanner v1.0.0 on ${data.metadata.generatedAt.toLocaleString()}</p>
    </div>
</body>
</html>`;
  }
}

// Markdown Report Exporter
class MarkdownReportExporter implements ReportExporter {
  format = ReportFormat.MARKDOWN;

  async export(report: VulnerabilityReport, options: ReportOptions): Promise<string> {
    let markdown = `# MCP Security Scan Report\n\n`;
    markdown += `Generated on ${report.generatedAt.toLocaleDateString()}\n\n`;
    
    // Summary section
    markdown += `## Summary\n\n`;
    markdown += `- **Total Vulnerabilities**: ${report.summary.totalVulnerabilities}\n`;
    markdown += `- **Risk Score**: ${report.summary.riskScore}/100\n`;
    markdown += `- **Files Scanned**: ${report.scanResult.targetInfo.totalFiles}\n`;
    markdown += `- **Scan Duration**: ${report.scanResult.metadata.scanDuration}ms\n\n`;
    
    // Vulnerability breakdown
    markdown += `## Vulnerability Breakdown\n\n`;
    Object.entries(report.summary.vulnerabilityBreakdown).forEach(([severity, count]) => {
      markdown += `- **${severity.toUpperCase()}**: ${count}\n`;
    });
    markdown += `\n`;
    
    // Detailed findings
    markdown += `## Detailed Findings\n\n`;
    report.scanResult.vulnerabilities.slice(0, 20).forEach(vuln => {
      markdown += `### ${vuln.title}\n\n`;
      markdown += `- **Severity**: ${vuln.severity.toUpperCase()}\n`;
      markdown += `- **File**: \`${vuln.location.file}:${vuln.location.line}\`\n`;
      markdown += `- **Description**: ${vuln.description}\n\n`;
      
      if (options.includeRemediation) {
        markdown += `**Remediation Steps**:\n`;
        vuln.remediation.steps.forEach(step => {
          markdown += `- ${step}\n`;
        });
        markdown += `\n`;
      }
    });
    
    return markdown;
  }

  validate(report: VulnerabilityReport): boolean {
    return report && report.scanResult && Array.isArray(report.scanResult.vulnerabilities);
  }
}

// CSV Report Exporter
class CsvReportExporter implements ReportExporter {
  format = ReportFormat.CSV;

  async export(report: VulnerabilityReport, options: ReportOptions): Promise<string> {
    const headers = [
      'ID',
      'Type',
      'Severity',
      'Score',
      'Title',
      'File',
      'Line',
      'Column',
      'Description',
      'Confidence',
      'False Positive Risk',
      'Detected At',
    ];

    const rows = report.scanResult.vulnerabilities.map(vuln => [
      vuln.id,
      vuln.type,
      vuln.severity,
      vuln.score.toString(),
      this.escapeCsv(vuln.title),
      vuln.location.file,
      vuln.location.line.toString(),
      vuln.location.column.toString(),
      this.escapeCsv(vuln.description),
      vuln.confidence.toString(),
      vuln.falsePositiveRisk,
      vuln.detectedAt.toISOString(),
    ]);

    return [headers, ...rows]
      .map(row => row.join(','))
      .join('\n');
  }

  validate(report: VulnerabilityReport): boolean {
    return report && report.scanResult && Array.isArray(report.scanResult.vulnerabilities);
  }

  private escapeCsv(value: string): string {
    if (value.includes(',') || value.includes('"') || value.includes('\n')) {
      return `"${value.replace(/"/g, '""')}"`;
    }
    return value;
  }
}

export const reportGenerator = new SecurityReportGenerator();
