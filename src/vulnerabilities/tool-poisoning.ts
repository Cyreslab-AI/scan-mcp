// Tool poisoning vulnerability detector for MCP security
import { VulnerabilityDetector, DetectionContext, PatternMatcher, SecurityUtils } from './base';
import { Vulnerability, VulnerabilityPattern, ToolPoisoningVuln } from '@/types/vulnerability';
import { LanguageAST } from '@/types/language';
import { LanguageType, SeverityLevel, VulnerabilityType } from '@/types';

export class ToolPoisoningDetector extends VulnerabilityDetector {
  constructor() {
    const patterns = TOOL_POISONING_PATTERNS;
    const supportedLanguages = [
      LanguageType.TYPESCRIPT,
      LanguageType.JAVASCRIPT,
      LanguageType.PYTHON,
    ];

    super(VulnerabilityType.TOOL_POISONING, supportedLanguages, patterns);
  }

  async detect(ast: LanguageAST, content: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    if (!this.supportsLanguage(ast.language)) {
      return vulnerabilities;
    }

    // Apply each pattern
    for (const pattern of this.patterns) {
      if (pattern.language === ast.language) {
        const matches = await this.detectPattern(ast, content, pattern);
        vulnerabilities.push(...matches);
      }
    }

    return vulnerabilities.filter(v => this.validateDetection(v));
  }

  private async detectPattern(
    ast: LanguageAST, 
    content: string, 
    pattern: VulnerabilityPattern
  ): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    if (pattern.pattern instanceof RegExp) {
      const matches = PatternMatcher.matchRegex(content, pattern.pattern);

      for (const match of matches) {
        const position = this.findPosition(content, match.index);
        const context = this.buildDetectionContext(ast, content, match, position);
        
        // Create enhanced tool poisoning vulnerability
        const toolPoisonVuln = this.createToolPoisoningVuln(
          pattern, 
          ast.filePath, 
          position, 
          context, 
          match
        );

        vulnerabilities.push(toolPoisonVuln);
      }
    }

    return vulnerabilities;
  }

  private buildDetectionContext(
    ast: LanguageAST,
    content: string,
    match: any,
    position: { line: number; column: number }
  ): DetectionContext {
    const codeSnippet = this.extractCodeSnippet(content, match.index, match.index + match.length);
    const functionName = this.extractFunctionName(content, match.index);

    return {
      language: ast.language,
      filePath: ast.filePath,
      ...(functionName && { functionName }),
      inPublicFunction: functionName ? SecurityUtils.isPublicFunction(functionName, content) : false,
      inSecurityCriticalFunction: functionName ? SecurityUtils.isSecurityCritical(functionName, codeSnippet) : false,
      hasUserInput: SecurityUtils.hasUserInput(codeSnippet),
      codeSnippet,
      astContext: {
        position,
        nodeType: 'ToolDefinition',
      },
    };
  }

  private extractFunctionName(content: string, position: number): string | undefined {
    const beforePosition = content.substring(0, position);
    const functionPatterns = [
      /function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/g,
      /const\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\(/g,
      /([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:\s*\(/g,
    ];

    for (const pattern of functionPatterns) {
      const matches = Array.from(beforePosition.matchAll(pattern));
      if (matches.length > 0) {
        const lastMatch = matches[matches.length - 1];
        return lastMatch?.[1];
      }
    }

    return undefined;
  }

  private createToolPoisoningVuln(
    pattern: VulnerabilityPattern,
    filePath: string,
    position: { line: number; column: number },
    context: DetectionContext,
    match: any
  ): ToolPoisoningVuln {
    const baseVuln = this.createVulnerability(
      pattern,
      {
        file: filePath,
        line: position.line,
        column: position.column,
        ...(context.functionName && { function: context.functionName }),
      },
      context,
      {
        toolMatch: match.match,
        poisonVector: this.identifyPoisonVector(match.match),
      }
    );

    // Extract tool poisoning specific details
    const poisonDetails = this.analyzeToolPoisoning(match.match, context);

    return {
      ...baseVuln,
      type: VulnerabilityType.TOOL_POISONING,
      tool: poisonDetails.tool,
      poisonVector: poisonDetails.poisonVector,
      maliciousPayload: poisonDetails.maliciousPayload,
      ...(poisonDetails.targetFunction && { targetFunction: poisonDetails.targetFunction }),
    };
  }

  private identifyPoisonVector(toolMatch: string): string {
    const poisonVectors = [
      { pattern: /exec\s*\(/gi, vector: 'Command execution in tool handler' },
      { pattern: /eval\s*\(/gi, vector: 'Code evaluation in tool' },
      { pattern: /spawn\s*\(/gi, vector: 'Process spawning in tool' },
      { pattern: /require\s*\(/gi, vector: 'Dynamic module loading' },
      { pattern: /import\s*\(/gi, vector: 'Dynamic import injection' },
      { pattern: /Function\s*\(/gi, vector: 'Function constructor abuse' },
      { pattern: /fs\.\w+/gi, vector: 'File system access' },
      { pattern: /process\.\w+/gi, vector: 'Process manipulation' },
      { pattern: /global\.\w+/gi, vector: 'Global object pollution' },
    ];

    for (const { pattern, vector } of poisonVectors) {
      if (pattern.test(toolMatch)) {
        return vector;
      }
    }

    return 'Generic tool poisoning';
  }

  private analyzeToolPoisoning(toolMatch: string, context: DetectionContext): ToolPoisoningAnalysis {
    const tool = this.extractToolName(toolMatch);
    const poisonVector = this.identifyPoisonVector(toolMatch);
    const maliciousPayload = this.extractMaliciousPayload(toolMatch);
    const targetFunction = this.extractTargetFunction(toolMatch, context);

    return {
      tool,
      poisonVector,
      maliciousPayload,
      ...(targetFunction && { targetFunction }),
    };
  }

  private extractToolName(toolMatch: string): string {
    // Extract tool name from various patterns
    const toolPatterns = [
      /tools\s*\[\s*['"`]([^'"`]+)['"`]\s*\]/,
      /tool\s*:\s*['"`]([^'"`]+)['"`]/,
      /name\s*:\s*['"`]([^'"`]+)['"`]/,
      /registerTool\s*\(\s*['"`]([^'"`]+)['"`]/,
      /addTool\s*\(\s*['"`]([^'"`]+)['"`]/,
    ];

    for (const pattern of toolPatterns) {
      const match = toolMatch.match(pattern);
      if (match && match[1]) {
        return match[1];
      }
    }

    return 'Unknown tool';
  }

  private extractMaliciousPayload(toolMatch: string): string {
    // Extract the malicious code from the tool definition
    const payloadPatterns = [
      /handler\s*:\s*[^,}]+/g,
      /execute\s*:\s*[^,}]+/g,
      /function\s*\([^)]*\)\s*{[^}]+}/g,
      /=>\s*{[^}]+}/g,
      /exec\s*\([^)]+\)/g,
      /eval\s*\([^)]+\)/g,
    ];

    for (const pattern of payloadPatterns) {
      const match = toolMatch.match(pattern);
      if (match) {
        return match[0];
      }
    }

    return 'Unidentified payload';
  }

  private extractTargetFunction(toolMatch: string, context: DetectionContext): string | undefined {
    // Try to identify what function is being targeted by the poisoning
    const functionContext = context.functionName;
    
    if (functionContext) {
      // Check if this is within a tool registration function
      const registrationPatterns = [
        /registerTool/i,
        /addTool/i,
        /defineTool/i,
        /createTool/i,
        /setupTool/i,
      ];

      if (registrationPatterns.some(pattern => pattern.test(functionContext))) {
        return functionContext;
      }
    }

    return undefined;
  }
}

// Tool poisoning analysis result
interface ToolPoisoningAnalysis {
  tool: string;
  poisonVector: string;
  maliciousPayload: string;
  targetFunction?: string;
}

// Tool poisoning patterns for MCP servers
const TOOL_POISONING_PATTERNS: VulnerabilityPattern[] = [
  {
    id: 'tool_poison_exec_handler',
    name: 'Tool Handler Command Execution',
    language: LanguageType.TYPESCRIPT,
    type: VulnerabilityType.TOOL_POISONING,
    severity: SeverityLevel.CRITICAL,
    pattern: /tools\s*\[[^\]]*\]\s*=\s*{[^}]*handler[^}]*exec\s*\(/gi,
    description: 'MCP tool handler directly executes system commands with user input',
    examples: {
      vulnerable: [
        'tools["executeCommand"] = { handler: (args) => exec(args.command) }',
        'tools.shellTool = { handler: ({ cmd }) => exec(cmd) }',
      ],
      safe: [
        'tools["safeCommand"] = { handler: (args) => validateAndExecute(args) }',
        'tools.calculator = { handler: ({ a, b }) => a + b }',
      ],
    },
    references: [
      'https://github.com/invariantlabs-ai/mcp-scan',
      'https://modelcontextprotocol.io/security',
    ],
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021 – Injection',
  },

  {
    id: 'tool_poison_eval_handler',
    name: 'Tool Handler Code Evaluation',
    language: LanguageType.JAVASCRIPT,
    type: VulnerabilityType.TOOL_POISONING,
    severity: SeverityLevel.CRITICAL,
    pattern: /handler\s*:[^}]*eval\s*\(|execute\s*:[^}]*eval\s*\(/gi,
    description: 'Tool handler uses eval() to execute user-provided code',
    examples: {
      vulnerable: [
        'handler: (args) => eval(args.code)',
        'execute: ({ script }) => eval(script)',
      ],
      safe: [
        'handler: (args) => safeExecute(args.code)',
        'execute: ({ data }) => processData(data)',
      ],
    },
    references: [
      'https://github.com/invariantlabs-ai/mcp-scan',
    ],
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021 – Injection',
  },

  {
    id: 'tool_poison_fs_access',
    name: 'Unrestricted File System Access in Tools',
    language: LanguageType.TYPESCRIPT,
    type: VulnerabilityType.TOOL_POISONING,
    severity: SeverityLevel.HIGH,
    pattern: /handler\s*:[^}]*fs\.\w+\s*\([^)]*args\.[^)]*\)/gi,
    description: 'Tool handlers provide unrestricted file system access with user input',
    examples: {
      vulnerable: [
        'handler: (args) => fs.readFile(args.path)',
        'handler: ({ filename }) => fs.writeFile(filename, data)',
      ],
      safe: [
        'handler: (args) => fs.readFile(path.join(safeDir, path.basename(args.path)))',
        'handler: ({ filename }) => fs.writeFile(validatePath(filename), data)',
      ],
    },
    references: [
      'https://owasp.org/www-community/attacks/Path_Traversal',
    ],
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021 – Broken Access Control',
  },

  {
    id: 'tool_poison_network_access',
    name: 'Unrestricted Network Access in Tools',
    language: LanguageType.JAVASCRIPT,
    type: VulnerabilityType.TOOL_POISONING,
    severity: SeverityLevel.HIGH,
    pattern: /handler\s*:[^}]*(fetch|axios|request|http\.get)\s*\([^)]*args\.[^)]*\)/gi,
    description: 'Tool handlers allow arbitrary network requests with user-controlled URLs',
    examples: {
      vulnerable: [
        'handler: (args) => fetch(args.url)',
        'handler: ({ endpoint }) => axios.get(endpoint)',
      ],
      safe: [
        'handler: (args) => fetch(validateURL(args.url))',
        'handler: ({ endpoint }) => axios.get(sanitizeEndpoint(endpoint))',
      ],
    },
    references: [
      'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
    ],
    cweId: 'CWE-918',
    owaspCategory: 'A10:2021 – Server-Side Request Forgery',
  },

  {
    id: 'tool_poison_process_access',
    name: 'Process Manipulation in Tool Handlers',
    language: LanguageType.TYPESCRIPT,
    type: VulnerabilityType.TOOL_POISONING,
    severity: SeverityLevel.HIGH,
    pattern: /handler\s*:[^}]*process\.(exit|kill|abort|chdir)/gi,
    description: 'Tool handlers can manipulate process state or terminate execution',
    examples: {
      vulnerable: [
        'handler: () => process.exit(0)',
        'handler: ({ signal }) => process.kill(process.pid, signal)',
      ],
      safe: [
        'handler: () => ({ result: "completed" })',
        'handler: ({ data }) => processData(data)',
      ],
    },
    references: [
      'https://nodejs.org/api/process.html#process_process_exit_code',
    ],
    cweId: 'CWE-250',
    owaspCategory: 'A04:2021 – Insecure Design',
  },

  {
    id: 'tool_poison_global_pollution',
    name: 'Global Object Pollution in Tools',
    language: LanguageType.JAVASCRIPT,
    type: VulnerabilityType.TOOL_POISONING,
    severity: SeverityLevel.MEDIUM,
    pattern: /handler\s*:[^}]*global\.\w+\s*=/gi,
    description: 'Tool handlers modify global objects, potentially affecting other code',
    examples: {
      vulnerable: [
        'handler: (args) => { global.config = args.config; }',
        'handler: ({ data }) => global.cache[data.key] = data.value',
      ],
      safe: [
        'handler: (args) => setLocalConfig(args.config)',
        'handler: ({ data }) => localCache.set(data.key, data.value)',
      ],
    },
    references: [
      'https://owasp.org/www-community/vulnerabilities/Object_Injection_(JavaScript)',
    ],
    cweId: 'CWE-915',
    owaspCategory: 'A04:2021 – Insecure Design',
  },

  {
    id: 'tool_poison_python_exec',
    name: 'Python Code Execution in Tools',
    language: LanguageType.PYTHON,
    type: VulnerabilityType.TOOL_POISONING,
    severity: SeverityLevel.CRITICAL,
    pattern: /def\s+\w+[^:]*:[^}]*exec\s*\(|lambda[^:]*:[^}]*eval\s*\(/gi,
    description: 'Python tool functions use exec() or eval() with user input',
    examples: {
      vulnerable: [
        'def execute_code(args): exec(args["code"])',
        'lambda data: eval(data["expression"])',
      ],
      safe: [
        'def execute_code(args): safe_execute(args["code"])',
        'lambda data: calculate(data["expression"])',
      ],
    },
    references: [
      'https://docs.python.org/3/library/functions.html#exec',
    ],
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021 – Injection',
  },
];

export const toolPoisoningDetector = new ToolPoisoningDetector();

// Tool poisoning analysis result
interface ToolPoisoningAnalysis {
  tool: string;
  poisonVector: string;
  maliciousPayload: string;
  targetFunction?: string;
}
