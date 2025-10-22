// Report generation and formatting types for MCP Security Scanner
import { ReportFormat, SeverityLevel } from './index';
import { ScanResult, ScanSummary } from './scan';
import { Vulnerability } from './vulnerability';

export interface ReportOptions {
  format: ReportFormat;
  template?: string;
  outputPath?: string;
  includeDetails: boolean;
  includeExploitProofs: boolean;
  includeRemediation: boolean;
  includeCVEReferences: boolean;
  includeCodeSnippets: boolean;
  minSeverity: SeverityLevel;
  customSections?: ReportSection[];
}

export interface ReportSection {
  id: string;
  title: string;
  content: string | ReportContent;
  order: number;
  enabled: boolean;
}

export interface ReportContent {
  type: 'text' | 'table' | 'chart' | 'code' | 'list';
  data: unknown;
  formatting?: Record<string, unknown>;
}

export interface VulnerabilityReport {
  id: string;
  scanResult: ScanResult;
  options: ReportOptions;
  summary: ReportSummary;
  sections: ReportSection[];
  generatedAt: Date;
  version: string;
}

export interface ReportSummary extends ScanSummary {
  executiveSummary: string;
  keyFindings: string[];
  riskAssessment: RiskAssessment;
  complianceStatus: ComplianceStatus;
  trendAnalysis?: TrendData;
}

export interface RiskAssessment {
  overallRisk: SeverityLevel;
  businessImpact: 'low' | 'medium' | 'high' | 'critical';
  exploitability: number; // 0-1
  attackSurface: number; // 0-1
  dataAtRisk: string[];
  mitigationPriority: MitigationItem[];
}

export interface MitigationItem {
  vulnerability: string;
  priority: number;
  effort: 'low' | 'medium' | 'high';
  impact: 'low' | 'medium' | 'high';
  timeline: string;
  resources: string[];
}

export interface ComplianceStatus {
  frameworks: ComplianceFramework[];
  overallScore: number; // 0-100
  gaps: ComplianceGap[];
  certifications: string[];
}

export interface ComplianceFramework {
  name: string;
  version: string;
  score: number; // 0-100
  requirements: ComplianceRequirement[];
}

export interface ComplianceRequirement {
  id: string;
  description: string;
  status: 'compliant' | 'partial' | 'non-compliant' | 'not-applicable';
  gaps: string[];
  evidence?: string[];
}

export interface ComplianceGap {
  requirement: string;
  severity: SeverityLevel;
  description: string;
  remediation: string;
  timeline: string;
}

export interface TrendData {
  historicalScans: HistoricalScan[];
  trends: {
    vulnerabilityTrend: number; // positive = increasing
    severityTrend: number;
    newVulnerabilities: number;
    fixedVulnerabilities: number;
  };
  predictions?: {
    riskForecast: number;
    timeToFix: number;
    effortEstimate: string;
  };
}

export interface HistoricalScan {
  scanId: string;
  date: Date;
  vulnerabilityCount: number;
  riskScore: number;
  version: string;
}

// SARIF (Static Analysis Results Interchange Format) types
export interface SarifReport {
  version: '2.1.0';
  $schema: string;
  runs: SarifRun[];
}

export interface SarifRun {
  tool: SarifTool;
  results: SarifResult[];
  artifacts?: SarifArtifact[];
  columnKind?: 'utf16CodeUnits' | 'unicodeCodePoints';
}

export interface SarifTool {
  driver: SarifDriver;
}

export interface SarifDriver {
  name: string;
  version: string;
  informationUri?: string;
  rules?: SarifRule[];
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: SarifMessage;
  fullDescription?: SarifMessage;
  help?: SarifMessage;
  defaultConfiguration?: SarifConfiguration;
  properties?: Record<string, unknown>;
}

export interface SarifMessage {
  text: string;
  markdown?: string;
}

export interface SarifConfiguration {
  level: 'note' | 'warning' | 'error';
  enabled?: boolean;
}

export interface SarifResult {
  ruleId: string;
  ruleIndex?: number;
  message: SarifMessage;
  level?: 'note' | 'warning' | 'error';
  locations?: SarifLocation[];
  fixes?: SarifFix[];
  properties?: Record<string, unknown>;
}

export interface SarifLocation {
  physicalLocation: SarifPhysicalLocation;
}

export interface SarifPhysicalLocation {
  artifactLocation: SarifArtifactLocation;
  region?: SarifRegion;
}

export interface SarifArtifactLocation {
  uri: string;
  uriBaseId?: string;
}

export interface SarifRegion {
  startLine: number;
  startColumn?: number;
  endLine?: number;
  endColumn?: number;
  snippet?: SarifArtifactContent;
}

export interface SarifArtifactContent {
  text: string;
}

export interface SarifFix {
  description: SarifMessage;
  artifactChanges: SarifArtifactChange[];
}

export interface SarifArtifactChange {
  artifactLocation: SarifArtifactLocation;
  replacements: SarifReplacement[];
}

export interface SarifReplacement {
  deletedRegion: SarifRegion;
  insertedContent?: SarifArtifactContent;
}

export interface SarifArtifact {
  location: SarifArtifactLocation;
  length?: number;
  mimeType?: string;
  contents?: SarifArtifactContent;
}

// HTML Report types
export interface HtmlReportOptions extends ReportOptions {
  theme: 'light' | 'dark' | 'auto';
  interactive: boolean;
  includeCharts: boolean;
  customCss?: string;
  embedAssets: boolean;
}

export interface HtmlReportData {
  title: string;
  subtitle: string;
  summary: ReportSummary;
  vulnerabilities: Vulnerability[];
  charts: ChartData[];
  metadata: HtmlReportMetadata;
}

export interface ChartData {
  type: 'pie' | 'bar' | 'line' | 'scatter' | 'heatmap';
  title: string;
  data: ChartDataPoint[];
  options?: Record<string, unknown>;
}

export interface ChartDataPoint {
  label: string;
  value: number;
  color?: string;
  metadata?: Record<string, unknown>;
}

export interface HtmlReportMetadata {
  generatedAt: Date;
  scannerVersion: string;
  reportVersion: string;
  theme: string;
  interactive: boolean;
  totalSize: number;
}

// Export utilities
export interface ReportExporter {
  format: ReportFormat;
  export(report: VulnerabilityReport, options: ReportOptions): Promise<string>;
  validate(report: VulnerabilityReport): boolean;
}

export interface ReportTemplate {
  id: string;
  name: string;
  format: ReportFormat;
  template: string;
  variables: TemplateVariable[];
  metadata: TemplateMetadata;
}

export interface TemplateVariable {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'date' | 'object';
  required: boolean;
  defaultValue?: unknown;
  description?: string;
}

export interface TemplateMetadata {
  author: string;
  version: string;
  description: string;
  tags: string[];
  createdAt: Date;
  updatedAt: Date;
}

export interface ReportArchive {
  reportId: string;
  format: ReportFormat;
  content: string | Buffer;
  metadata: ArchiveMetadata;
}

export interface ArchiveMetadata {
  scanId: string;
  generatedAt: Date;
  size: number;
  checksum: string;
  compressed: boolean;
  encryption?: {
    algorithm: string;
    keyId: string;
  };
}
