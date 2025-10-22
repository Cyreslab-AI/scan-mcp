// Secure MCP server implementation with comprehensive input sanitization
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { 
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';

import { securityAnalyzer } from '@/analyzer/core';
import { vulnerabilityPatternDatabase } from '@/database/vulnerability-patterns';
import { cveMappingDatabase } from '@/database/cve-mappings';
import { ScanOptions } from '@/types/scan';
import { AnalysisType, SeverityLevel } from '@/types';

export class McpSecurityServer {
  private server: Server;
  private isInitialized = false;

  constructor() {
    this.server = new Server(
      {
        name: 'mcp-security-scanner',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
          resources: {},
        },
      }
    );

    this.setupToolHandlers();
    this.setupResourceHandlers();
  }

  /**
   * Setup MCP tool handlers with input sanitization
   */
  private setupToolHandlers(): void {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: 'scan_mcp_server',
            description: 'Perform comprehensive security scan on MCP server code',
            inputSchema: {
              type: 'object',
              properties: {
                source: {
                  type: 'string',
                  description: 'Path to MCP server source code or directory',
                },
                options: {
                  type: 'object',
                  description: 'Scan configuration options',
                  properties: {
                    analysisType: {
                      type: 'string',
                      enum: ['static', 'dynamic', 'hybrid'],
                      description: 'Type of analysis to perform',
                      default: 'hybrid',
                    },
                    targetLanguages: {
                      type: 'array',
                      items: { 
                        type: 'string',
                        enum: ['typescript', 'javascript', 'python', 'go', 'rust'],
                      },
                      description: 'Target programming languages to scan',
                    },
                    severityThreshold: {
                      type: 'string',
                      enum: ['critical', 'high', 'medium', 'low', 'info'],
                      description: 'Minimum severity level to report',
                      default: 'medium',
                    },
                    includePaths: {
                      type: 'array',
                      items: { type: 'string' },
                      description: 'Paths to include in scan',
                    },
                    excludePaths: {
                      type: 'array',
                      items: { type: 'string' },
                      description: 'Paths to exclude from scan',
                    },
                    maxDepth: {
                      type: 'number',
                      minimum: 1,
                      maximum: 20,
                      description: 'Maximum directory depth to scan',
                      default: 10,
                    },
                    timeout: {
                      type: 'number',
                      minimum: 1000,
                      maximum: 300000,
                      description: 'Scan timeout in milliseconds',
                      default: 60000,
                    },
                  },
                },
              },
              required: ['source'],
              additionalProperties: false,
            },
          },

          {
            name: 'get_vulnerability_patterns',
            description: 'Get available vulnerability patterns and rules',
            inputSchema: {
              type: 'object',
              properties: {
                language: {
                  type: 'string',
                  enum: ['typescript', 'javascript', 'python', 'go', 'rust'],
                  description: 'Filter patterns by programming language',
                },
                type: {
                  type: 'string',
                  enum: ['command_injection', 'path_traversal', 'prompt_injection', 'tool_poisoning'],
                  description: 'Filter patterns by vulnerability type',
                },
                severity: {
                  type: 'string',
                  enum: ['critical', 'high', 'medium', 'low'],
                  description: 'Filter patterns by severity level',
                },
              },
              additionalProperties: false,
            },
          },

          {
            name: 'validate_mcp_config',
            description: 'Validate MCP server configuration for security issues',
            inputSchema: {
              type: 'object',
              properties: {
                config: {
                  type: 'object',
                  description: 'MCP server configuration to validate',
                },
                strict: {
                  type: 'boolean',
                  description: 'Enable strict validation mode',
                  default: false,
                },
              },
              required: ['config'],
              additionalProperties: false,
            },
          },

          {
            name: 'get_cve_information',
            description: 'Get CVE information related to MCP security',
            inputSchema: {
              type: 'object',
              properties: {
                cveId: {
                  type: 'string',
                  pattern: '^CVE-\\d{4}-\\d{4,}$',
                  description: 'Specific CVE ID to lookup',
                },
                severity: {
                  type: 'string',
                  enum: ['critical', 'high', 'medium', 'low'],
                  description: 'Filter by severity level',
                },
                keywords: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Search keywords',
                },
              },
              additionalProperties: false,
            },
          },
        ],
      };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        // Sanitize all inputs before processing
        const sanitizedArgs = this.sanitizeToolInputs(name, args);
        
        switch (name) {
          case 'scan_mcp_server':
            return await this.handleScanRequest(sanitizedArgs);
            
          case 'get_vulnerability_patterns':
            return await this.handleGetPatternsRequest(sanitizedArgs);
            
          case 'validate_mcp_config':
            return await this.handleValidateConfigRequest(sanitizedArgs);
            
          case 'get_cve_information':
            return await this.handleGetCVERequest(sanitizedArgs);
            
          default:
            throw new McpError(
              ErrorCode.MethodNotFound,
              `Unknown tool: ${name}`
            );
        }
      } catch (error) {
        throw new McpError(
          ErrorCode.InternalError,
          `Tool execution failed: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
      }
    });
  }

  /**
   * Setup MCP resource handlers
   */
  private setupResourceHandlers(): void {
    // Note: Resource handlers temporarily simplified to fix TypeScript issues
    // Full implementation would use proper MCP SDK resource schemas
  }

  /**
   * Comprehensive input sanitization for all tool inputs
   */
  private sanitizeToolInputs(_toolName: string, args: any): any {
    if (!args || typeof args !== 'object') {
      return {};
    }

    const sanitized = { ...args };

    // Sanitize file paths
    if (sanitized.source) {
      sanitized.source = this.sanitizeFilePath(sanitized.source);
    }

    // Sanitize arrays
    if (sanitized.includePaths && Array.isArray(sanitized.includePaths)) {
      sanitized.includePaths = sanitized.includePaths
        .filter((path: any) => typeof path === 'string')
        .map((path: string) => this.sanitizeFilePath(path));
    }

    if (sanitized.excludePaths && Array.isArray(sanitized.excludePaths)) {
      sanitized.excludePaths = sanitized.excludePaths
        .filter((path: any) => typeof path === 'string')
        .map((path: string) => this.sanitizeFilePath(path));
    }

    // Sanitize numbers
    if (sanitized.maxDepth !== undefined) {
      sanitized.maxDepth = this.sanitizeNumber(sanitized.maxDepth, 1, 20, 10);
    }

    if (sanitized.timeout !== undefined) {
      sanitized.timeout = this.sanitizeNumber(sanitized.timeout, 1000, 300000, 60000);
    }

    // Sanitize enums
    if (sanitized.analysisType) {
      sanitized.analysisType = this.sanitizeEnum(
        sanitized.analysisType,
        ['static', 'dynamic', 'hybrid'],
        'hybrid'
      );
    }

    if (sanitized.severityThreshold) {
      sanitized.severityThreshold = this.sanitizeEnum(
        sanitized.severityThreshold,
        ['critical', 'high', 'medium', 'low', 'info'],
        'medium'
      );
    }

    // Sanitize strings
    if (sanitized.cveId) {
      sanitized.cveId = this.sanitizeCVEId(sanitized.cveId);
    }

    // Remove any potentially dangerous properties
    const dangerousProps = ['__proto__', 'constructor', 'prototype'];
    for (const prop of dangerousProps) {
      delete sanitized[prop];
    }

    return sanitized;
  }

  /**
   * Sanitize file paths to prevent path traversal
   */
  private sanitizeFilePath(filePath: any): string {
    if (typeof filePath !== 'string') {
      throw new McpError(ErrorCode.InvalidParams, 'File path must be a string');
    }

    // Remove dangerous sequences
    let sanitized = filePath
      .replace(/\.\./g, '') // Remove path traversal
      .replace(/[|&;`$()]/g, '') // Remove command injection chars
      .replace(/\0/g, '') // Remove null bytes
      .trim();

    // Validate length
    if (sanitized.length === 0) {
      throw new McpError(ErrorCode.InvalidParams, 'File path cannot be empty');
    }

    if (sanitized.length > 1000) {
      throw new McpError(ErrorCode.InvalidParams, 'File path too long');
    }

    // Ensure it's a reasonable path
    if (!/^[a-zA-Z0-9._/-]+$/.test(sanitized)) {
      throw new McpError(ErrorCode.InvalidParams, 'File path contains invalid characters');
    }

    return sanitized;
  }

  /**
   * Sanitize numeric inputs
   */
  private sanitizeNumber(value: any, min: number, max: number, defaultValue: number): number {
    if (typeof value === 'string') {
      value = parseInt(value, 10);
    }

    if (typeof value !== 'number' || isNaN(value)) {
      return defaultValue;
    }

    return Math.min(max, Math.max(min, value));
  }

  /**
   * Sanitize enum values
   */
  private sanitizeEnum(value: any, allowedValues: string[], defaultValue: string): string {
    if (typeof value !== 'string' || !allowedValues.includes(value)) {
      return defaultValue;
    }
    return value;
  }

  /**
   * Sanitize CVE ID format
   */
  private sanitizeCVEId(cveId: any): string {
    if (typeof cveId !== 'string') {
      throw new McpError(ErrorCode.InvalidParams, 'CVE ID must be a string');
    }

    const cvePattern = /^CVE-\d{4}-\d{4,}$/;
    if (!cvePattern.test(cveId)) {
      throw new McpError(ErrorCode.InvalidParams, 'Invalid CVE ID format');
    }

    return cveId;
  }

  /**
   * Handle scan request with comprehensive validation
   */
  private async handleScanRequest(args: any): Promise<any> {
    const { source, options = {} } = args;

    // Build scan options with defaults and validation
    const scanOptions: ScanOptions = {
      analysisType: (options.analysisType as AnalysisType) || AnalysisType.HYBRID,
      targetLanguages: options.targetLanguages || [],
      includePaths: options.includePaths || [],
      excludePaths: options.excludePaths || ['node_modules', '.git', 'dist'],
      maxDepth: options.maxDepth || 10,
      timeout: options.timeout || 60000,
      concurrent: options.concurrent || false,
      maxConcurrency: options.maxConcurrency || 4,
      enableDynamicAnalysis: options.analysisType !== 'static',
      enableStaticAnalysis: options.analysisType !== 'dynamic',
      severityThreshold: (options.severityThreshold as SeverityLevel) || SeverityLevel.MEDIUM,
    };

    // Perform the scan
    const scanResult = await securityAnalyzer.scanServer(source, scanOptions);

    // Format results for MCP response
    return {
      content: [
        {
          type: 'text',
          text: `# Security Scan Results

## Summary
- **Total Vulnerabilities**: ${scanResult.summary.totalVulnerabilities}
- **Risk Score**: ${scanResult.summary.riskScore}/100
- **Files Scanned**: ${scanResult.targetInfo.totalFiles}
- **Scan Duration**: ${scanResult.metadata.scanDuration}ms

## Vulnerability Breakdown
${Object.entries(scanResult.summary.vulnerabilityBreakdown)
  .map(([severity, count]) => `- **${severity.toUpperCase()}**: ${count}`)
  .join('\n')}

## Recommendations
${scanResult.summary.recommendedActions.map(action => `- ${action}`).join('\n')}

## Detailed Findings
${scanResult.vulnerabilities.slice(0, 10).map(vuln => 
  `### ${vuln.title}\n- **Severity**: ${vuln.severity}\n- **File**: ${vuln.location.file}:${vuln.location.line}\n- **Description**: ${vuln.description}\n`
).join('\n')}

${scanResult.vulnerabilities.length > 10 ? `\n*... and ${scanResult.vulnerabilities.length - 10} more vulnerabilities*` : ''}
`,
        },
        {
          type: 'text',
          text: JSON.stringify(scanResult, null, 2),
        },
      ],
    };
  }

  /**
   * Handle vulnerability patterns request
   */
  private async handleGetPatternsRequest(args: any): Promise<any> {
    const { language, type, severity } = args;

    let patterns = vulnerabilityPatternDatabase.getAllPatterns();

    // Apply filters
    if (language) {
      patterns = patterns.filter(p => p.language === language);
    }
    
    if (type) {
      patterns = patterns.filter(p => p.type === type);
    }
    
    if (severity) {
      patterns = patterns.filter(p => p.severity === severity);
    }

    return {
      content: [
        {
          type: 'text',
          text: `Found ${patterns.length} vulnerability patterns matching your criteria:\n\n${patterns.map(p => 
            `**${p.name}** (${p.language})\n- Severity: ${p.severity}\n- Type: ${p.type}\n- Description: ${p.description}`
          ).join('\n\n')}`,
        },
        {
          type: 'text',
          text: JSON.stringify(patterns, null, 2),
        },
      ],
    };
  }

  /**
   * Handle MCP config validation request
   */
  private async handleValidateConfigRequest(args: any): Promise<any> {
    const { config, strict = false } = args;

    const validationResults = {
      valid: true,
      issues: [] as string[],
      recommendations: [] as string[],
      securityScore: 100,
    };

    // Validate transport security
    if (config.transport?.type === 'http' && !config.transport?.ssl) {
      validationResults.issues.push('HTTP transport without SSL/TLS encryption');
      validationResults.securityScore -= 20;
    }

    // Validate tool definitions
    if (config.tools) {
      for (const [toolName, toolDef] of Object.entries(config.tools)) {
        const toolValidation = this.validateToolDefinition(toolName, toolDef, strict);
        if (!toolValidation.valid) {
          validationResults.issues.push(...toolValidation.issues.map(issue => `Tool ${toolName}: ${issue}`));
          validationResults.securityScore -= 10;
        }
      }
    }

    // Provide recommendations
    if (validationResults.securityScore < 80) {
      validationResults.recommendations.push('Consider implementing additional security controls');
    }

    validationResults.valid = validationResults.issues.length === 0;

    return {
      content: [
        {
          type: 'text',
          text: `# MCP Configuration Validation

## Overall Result: ${validationResults.valid ? '✅ VALID' : '❌ INVALID'}
## Security Score: ${validationResults.securityScore}/100

${validationResults.issues.length > 0 ? `## Issues Found\n${validationResults.issues.map(issue => `- ${issue}`).join('\n')}\n` : ''}

${validationResults.recommendations.length > 0 ? `## Recommendations\n${validationResults.recommendations.map(rec => `- ${rec}`).join('\n')}` : ''}`,
        },
      ],
    };
  }

  /**
   * Handle CVE information request
   */
  private async handleGetCVERequest(args: any): Promise<any> {
    const { cveId, severity, keywords = [] } = args;

    let cveEntries = cveMappingDatabase.getDatabase().entries;

    // Apply filters
    if (cveId) {
      const entry = cveMappingDatabase.getCVE(cveId);
      cveEntries = entry ? [entry] : [];
    } else {
      if (severity) {
        cveEntries = cveMappingDatabase.getCVEsBySeverity(severity as SeverityLevel);
      }
      
      if (keywords.length > 0) {
        cveEntries = cveMappingDatabase.searchCVEs(keywords);
      }
    }

    return {
      content: [
        {
          type: 'text',
          text: `# CVE Information\n\nFound ${cveEntries.length} CVE entries:\n\n${cveEntries.slice(0, 5).map(cve => 
            `## ${cve.id}\n- **Severity**: ${cve.severity} (${cve.score})\n- **Description**: ${cve.description}\n- **Published**: ${cve.published.toDateString()}`
          ).join('\n\n')}${cveEntries.length > 5 ? `\n\n*... and ${cveEntries.length - 5} more entries*` : ''}`,
        },
      ],
    };
  }

  /**
   * Validate tool definition for security issues
   */
  private validateToolDefinition(toolName: string, toolDef: any, strict: boolean): { valid: boolean; issues: string[] } {
    const issues: string[] = [];

    // Check for dangerous tool names
    const dangerousNames = ['exec', 'eval', 'shell', 'system', 'command'];
    if (dangerousNames.some(name => toolName.toLowerCase().includes(name))) {
      issues.push('Tool name suggests potentially dangerous functionality');
    }

    // Check input schema
    if (!toolDef.inputSchema || typeof toolDef.inputSchema !== 'object') {
      issues.push('Missing or invalid input schema');
    } else {
      // Validate schema has proper validation
      if (!toolDef.inputSchema.additionalProperties === false && strict) {
        issues.push('Input schema allows additional properties (security risk)');
      }
    }

    return {
      valid: issues.length === 0,
      issues,
    };
  }

  /**
   * Initialize and start the MCP server
   */
  async start(): Promise<void> {
    if (this.isInitialized) {
      throw new Error('Server already initialized');
    }

    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    
    this.isInitialized = true;
    console.error('MCP Security Scanner Server started successfully');
  }

  /**
   * Stop the MCP server
   */
  async stop(): Promise<void> {
    if (this.isInitialized) {
      await this.server.close();
      this.isInitialized = false;
    }
  }
}

// Create and export server instance
export const mcpSecurityServer = new McpSecurityServer();
