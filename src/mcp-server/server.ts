// Secure MCP server implementation with comprehensive input sanitization
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { Server, ProtocolError, ProtocolErrorCode } from '@modelcontextprotocol/server';

import { securityAnalyzer } from '@/analyzer/core';
import { vulnerabilityPatternDatabase } from '@/database/vulnerability-patterns';
import { cveMappingDatabase } from '@/database/cve-mappings';
import { ScanOptions } from '@/types/scan';
import { AnalysisType, SeverityLevel } from '@/types';

/**
 * JSON Schema describing the structured shape of a ScanResult (see src/types/scan.ts),
 * as actually produced by SecurityAnalyzer.scanServer() and returned by scan_mcp_server.
 */
const SCAN_RESULT_OUTPUT_SCHEMA = {
  type: 'object',
  description: 'Result of a comprehensive MCP server security scan',
  properties: {
    scanId: { type: 'string' },
    targetInfo: {
      type: 'object',
      properties: {
        totalFiles: { type: 'number' },
        totalLines: { type: 'number' },
        languageBreakdown: { type: 'object', additionalProperties: { type: 'number' } },
        dependencies: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              name: { type: 'string' },
              version: { type: 'string' },
              source: { type: 'string', enum: ['npm', 'pip', 'cargo', 'go.mod', 'unknown'] },
              vulnerabilities: { type: 'array', items: { type: 'string' } },
              outdated: { type: 'boolean' },
              license: { type: 'string' },
            },
          },
        },
      },
    },
    scanOptions: { type: 'object', additionalProperties: true },
    progress: { type: 'object', additionalProperties: true },
    vulnerabilities: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          type: { type: 'string' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
          score: { type: 'number' },
          title: { type: 'string' },
          description: { type: 'string' },
          location: {
            type: 'object',
            properties: {
              file: { type: 'string' },
              line: { type: 'number' },
              column: { type: 'number' },
              length: { type: 'number' },
              function: { type: 'string' },
              class: { type: 'string' },
              method: { type: 'string' },
            },
            required: ['file', 'line', 'column'],
          },
          remediation: {
            type: 'object',
            properties: {
              title: { type: 'string' },
              description: { type: 'string' },
              steps: { type: 'array', items: { type: 'string' } },
              codeExample: { type: 'string' },
              references: { type: 'array', items: { type: 'string' } },
              effort: { type: 'string', enum: ['low', 'medium', 'high'] },
              priority: { type: 'number' },
            },
          },
          cveReferences: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                id: { type: 'string' },
                url: { type: 'string' },
                description: { type: 'string' },
                score: { type: 'number' },
                vector: { type: 'string' },
              },
            },
          },
          confidence: { type: 'number' },
          falsePositiveRisk: { type: 'string', enum: ['low', 'medium', 'high'] },
          tags: { type: 'array', items: { type: 'string' } },
        },
        required: ['id', 'type', 'severity', 'title', 'description', 'location'],
      },
    },
    summary: {
      type: 'object',
      properties: {
        totalVulnerabilities: { type: 'number' },
        vulnerabilityBreakdown: { type: 'object', additionalProperties: { type: 'number' } },
        typeBreakdown: { type: 'object', additionalProperties: { type: 'number' } },
        riskScore: { type: 'number' },
        confidence: { type: 'number' },
        falsePositiveEstimate: { type: 'number' },
        recommendedActions: { type: 'array', items: { type: 'string' } },
      },
    },
    metadata: {
      type: 'object',
      properties: {
        scannerVersion: { type: 'string' },
        scanDuration: { type: 'number' },
        rulesVersion: { type: 'string' },
        environment: { type: 'object', additionalProperties: true },
        performance: { type: 'object', additionalProperties: true },
      },
    },
    generatedAt: { type: 'string', format: 'date-time' },
  },
  required: ['scanId', 'vulnerabilities', 'summary'],
} as const;

/**
 * JSON Schema for the response of get_vulnerability_patterns, based on the
 * VulnerabilityPattern shape in src/types/vulnerability.ts.
 */
const VULNERABILITY_PATTERNS_OUTPUT_SCHEMA = {
  type: 'object',
  properties: {
    count: { type: 'number' },
    patterns: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          name: { type: 'string' },
          language: { type: 'string' },
          type: { type: 'string' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
          description: { type: 'string' },
          examples: {
            type: 'object',
            properties: {
              vulnerable: { type: 'array', items: { type: 'string' } },
              safe: { type: 'array', items: { type: 'string' } },
            },
          },
          references: { type: 'array', items: { type: 'string' } },
          cweId: { type: 'string' },
          owaspCategory: { type: 'string' },
        },
        required: ['id', 'name', 'language', 'type', 'severity'],
      },
    },
  },
  required: ['count', 'patterns'],
} as const;

/**
 * JSON Schema for the response of validate_mcp_config, matching the
 * validationResults object built in handleValidateConfigRequest.
 */
const VALIDATE_CONFIG_OUTPUT_SCHEMA = {
  type: 'object',
  properties: {
    valid: { type: 'boolean' },
    issues: { type: 'array', items: { type: 'string' } },
    recommendations: { type: 'array', items: { type: 'string' } },
    securityScore: { type: 'number' },
  },
  required: ['valid', 'issues', 'recommendations', 'securityScore'],
} as const;

/**
 * JSON Schema for the response of get_cve_information, based on the
 * CVEEntry shape in src/types/database.ts (local, hard-coded CVE mapping data).
 */
const CVE_INFORMATION_OUTPUT_SCHEMA = {
  type: 'object',
  properties: {
    count: { type: 'number' },
    entries: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          description: { type: 'string' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
          score: { type: 'number' },
          vector: { type: 'string' },
          published: { type: 'string', format: 'date-time' },
          modified: { type: 'string', format: 'date-time' },
          references: { type: 'array', items: { type: 'string' } },
          affectedProducts: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                vendor: { type: 'string' },
                product: { type: 'string' },
                versions: { type: 'array', items: { type: 'object', additionalProperties: true } },
                platforms: { type: 'array', items: { type: 'string' } },
              },
            },
          },
          weaknesses: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                id: { type: 'string' },
                name: { type: 'string' },
                description: { type: 'string' },
                category: { type: 'string' },
              },
            },
          },
          exploitability: { type: 'object', additionalProperties: true },
          impact: { type: 'object', additionalProperties: true },
        },
        required: ['id', 'description', 'severity', 'score'],
      },
    },
  },
  required: ['count', 'entries'],
} as const;

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
    this.server.setRequestHandler('tools/list', async (): Promise<any> => {
      return {
        tools: [
          {
            name: 'scan_mcp_server',
            description: 'Perform a comprehensive security scan on MCP server code: static ' +
              'AST/regex analysis for command injection, path traversal, and prompt injection; ' +
              'tool-poisoning detection for BOTH dangerous handler code and malicious/hidden ' +
              'instructions embedded in tool descriptions or metadata; Dockerfile linting ' +
              '(unpinned base images, apt-get layering, missing non-root USER, ADD-vs-COPY, ' +
              'secrets in ENV/ARG); hardcoded-secret scanning (regex + entropy); and dependency ' +
              'vulnerability scanning of package.json/requirements.txt against the live OSV.dev database.',
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
                        enum: ['typescript', 'javascript', 'python', 'go', 'rust', 'dockerfile'],
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
            outputSchema: SCAN_RESULT_OUTPUT_SCHEMA,
            annotations: {
              readOnlyHint: true,
              // Reads local source files / Docker images passed in `source`. As of the
              // dependency-vulnerability scanner, this now also makes outbound HTTPS requests to
              // the public OSV.dev API to check package.json/requirements.txt dependencies -
              // network failures there are handled gracefully and never fail the overall scan.
              openWorldHint: true,
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
                  enum: ['typescript', 'javascript', 'python', 'go', 'rust', 'dockerfile', 'json'],
                  description: 'Filter patterns by programming language',
                },
                type: {
                  type: 'string',
                  enum: [
                    'command_injection',
                    'path_traversal',
                    'prompt_injection',
                    'tool_poisoning',
                    'oauth_vulnerability',
                    'dockerfile_misconfiguration',
                    'hardcoded_secret',
                    'dependency_vulnerability',
                  ],
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
            outputSchema: VULNERABILITY_PATTERNS_OUTPUT_SCHEMA,
            annotations: {
              readOnlyHint: true,
              // Looks up patterns from the local, in-memory pattern database only.
              openWorldHint: false,
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
            outputSchema: VALIDATE_CONFIG_OUTPUT_SCHEMA,
            annotations: {
              readOnlyHint: true,
              // Validates a config object passed in by the caller; no external calls.
              openWorldHint: false,
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
            outputSchema: CVE_INFORMATION_OUTPUT_SCHEMA,
            annotations: {
              readOnlyHint: true,
              // cveMappingDatabase is a local, hard-coded set of known MCP-related CVEs
              // (see src/database/cve-mappings.ts) — it does not query a live CVE feed.
              openWorldHint: false,
            },
          },
        ],
      };
    });

    this.server.setRequestHandler('tools/call', async (request) => {
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
            throw new ProtocolError(
              ProtocolErrorCode.MethodNotFound,
              `Unknown tool: ${name}`
            );
        }
      } catch (error) {
        throw new ProtocolError(
          ProtocolErrorCode.InternalError,
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
      throw new ProtocolError(ProtocolErrorCode.InvalidParams, 'File path must be a string');
    }

    // Remove dangerous sequences
    let sanitized = filePath
      .replace(/\.\./g, '') // Remove path traversal
      .replace(/[|&;`$()]/g, '') // Remove command injection chars
      .replace(/\0/g, '') // Remove null bytes
      .trim();

    // Validate length
    if (sanitized.length === 0) {
      throw new ProtocolError(ProtocolErrorCode.InvalidParams, 'File path cannot be empty');
    }

    if (sanitized.length > 1000) {
      throw new ProtocolError(ProtocolErrorCode.InvalidParams, 'File path too long');
    }

    // Ensure it's a reasonable path
    if (!/^[a-zA-Z0-9._/-]+$/.test(sanitized)) {
      throw new ProtocolError(ProtocolErrorCode.InvalidParams, 'File path contains invalid characters');
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
      throw new ProtocolError(ProtocolErrorCode.InvalidParams, 'CVE ID must be a string');
    }

    const cvePattern = /^CVE-\d{4}-\d{4,}$/;
    if (!cvePattern.test(cveId)) {
      throw new ProtocolError(ProtocolErrorCode.InvalidParams, 'Invalid CVE ID format');
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
      structuredContent: scanResult,
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
      structuredContent: {
        count: patterns.length,
        patterns,
      },
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
      structuredContent: validationResults,
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
      structuredContent: {
        count: cveEntries.length,
        entries: cveEntries,
      },
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
