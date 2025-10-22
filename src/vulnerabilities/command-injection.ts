// Command injection vulnerability detector
import { VulnerabilityDetector, DetectionContext, PatternMatcher, SecurityUtils } from './base';
import { Vulnerability, VulnerabilityPattern, CommandInjectionVuln } from '@/types/vulnerability';
import { LanguageAST } from '@/types/language';
import { LanguageType, SeverityLevel, VulnerabilityType } from '@/types';

export class CommandInjectionDetector extends VulnerabilityDetector {
  constructor() {
    const patterns = COMMAND_INJECTION_PATTERNS;
    const supportedLanguages = [
      LanguageType.TYPESCRIPT,
      LanguageType.JAVASCRIPT,
      LanguageType.PYTHON,
    ];

    super(VulnerabilityType.COMMAND_INJECTION, supportedLanguages, patterns);
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
        
        // Create enhanced command injection vulnerability
        const commandInjVuln = this.createCommandInjectionVuln(
          pattern, 
          ast.filePath, 
          position, 
          context, 
          match
        );

        vulnerabilities.push(commandInjVuln);
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
        nodeType: 'CallExpression',
      },
    };
  }

  private extractFunctionName(content: string, position: number): string | undefined {
    // Find the containing function by searching backwards for function declarations
    const beforePosition = content.substring(0, position);
    const functionPatterns = [
      /function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/g,
      /const\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\(/g,
      /([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:\s*\(/g, // Method in object
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

  private createCommandInjectionVuln(
    pattern: VulnerabilityPattern,
    filePath: string,
    position: { line: number; column: number },
    context: DetectionContext,
    match: any
  ): CommandInjectionVuln {
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
        commandMatch: match.match,
        injectionPoint: this.identifyInjectionPoint(match.match),
      }
    );

    // Extract command injection specific details
    const injectionDetails = this.analyzeCommandInjection(match.match);

    return {
      ...baseVuln,
      type: VulnerabilityType.COMMAND_INJECTION,
      injectionPoint: injectionDetails.injectionPoint,
      command: injectionDetails.command,
      userInput: injectionDetails.userInput,
      ...(injectionDetails.sanitization && { sanitization: injectionDetails.sanitization }),
    };
  }

  private identifyInjectionPoint(commandMatch: string): string {
    // Identify the specific point where injection occurs
    const injectionPatterns = [
      { pattern: /\$\{([^}]+)\}/, description: 'Template literal injection' },
      { pattern: /\+\s*([a-zA-Z_$][a-zA-Z0-9_$]*)/, description: 'String concatenation injection' },
      { pattern: /`[^`]*\$\{[^}]*\}[^`]*`/, description: 'Template string injection' },
    ];

    for (const { pattern, description } of injectionPatterns) {
      if (pattern.test(commandMatch)) {
        return description;
      }
    }

    return 'Unknown injection point';
  }

  private analyzeCommandInjection(commandMatch: string): CommandInjectionAnalysis {
    // Extract command details
    const command = this.extractBaseCommand(commandMatch);
    const userInput = this.extractUserInput(commandMatch);
    const sanitization = this.checkExistingSanitization(commandMatch);

    return {
      injectionPoint: this.identifyInjectionPoint(commandMatch),
      command,
      userInput,
      ...(sanitization.length > 0 && { sanitization }),
    };
  }

  private extractBaseCommand(commandMatch: string): string {
    // Extract the base command being executed
    const commandPatterns = [
      /exec\(\s*['"`]([^'"`]+)['"`]/,
      /spawn\(\s*['"`]([^'"`]+)['"`]/,
      /execSync\(\s*['"`]([^'"`]+)['"`]/,
    ];

    for (const pattern of commandPatterns) {
      const match = commandMatch.match(pattern);
      if (match && match[1]) {
        return match[1];
      }
    }

    return 'Unknown command';
  }

  private extractUserInput(commandMatch: string): string {
    // Extract user input variables/expressions
    const userInputPatterns = [
      /\$\{([^}]+)\}/g,
      /\+\s*([a-zA-Z_$][a-zA-Z0-9_$]*)/g,
    ];

    const inputs: string[] = [];
    for (const pattern of userInputPatterns) {
      const matches = Array.from(commandMatch.matchAll(pattern));
      for (const match of matches) {
        if (match[1]) {
          inputs.push(match[1]);
        }
      }
    }

    return inputs.join(', ') || 'Unknown user input';
  }

  private checkExistingSanitization(commandMatch: string): string[] {
    // Check for existing sanitization attempts
    const sanitizationPatterns = [
      'escape',
      'sanitize',
      'clean',
      'validate',
      'filter',
      'encode',
    ];

    const found: string[] = [];
    for (const pattern of sanitizationPatterns) {
      if (commandMatch.toLowerCase().includes(pattern)) {
        found.push(pattern);
      }
    }

    return found;
  }
}

// Command injection analysis result
interface CommandInjectionAnalysis {
  injectionPoint: string;
  command: string;
  userInput: string;
  sanitization?: string[];
}

// Command injection patterns for different languages
const COMMAND_INJECTION_PATTERNS: VulnerabilityPattern[] = [
  {
    id: 'cmd_inject_exec_template',
    name: 'Shell Command Execution with Template Literals',
    language: LanguageType.TYPESCRIPT,
    type: VulnerabilityType.COMMAND_INJECTION,
    severity: SeverityLevel.CRITICAL,
    pattern: /exec\s*\(\s*`[^`]*\$\{[^}]*\}[^`]*`\s*\)/g,
    description: 'Direct execution of shell commands with template literal interpolation allowing command injection',
    examples: {
      vulnerable: [
        'exec(`rm -rf ${userInput}`)',
        'exec(`cat ${filename} > output.txt`)',
        'exec(`find ${directory} -name "*.txt"`)',
      ],
      safe: [
        'execFile("rm", ["-rf", userInput])',
        'spawn("cat", [filename], { stdio: ["pipe", "pipe", "pipe"] })',
        'execFile("find", [directory, "-name", "*.txt"])',
      ],
    },
    references: [
      'https://owasp.org/www-community/attacks/Command_Injection',
      'https://cwe.mitre.org/data/definitions/78.html',
    ],
    cweId: 'CWE-78',
    owaspCategory: 'A03:2021 – Injection',
  },

  {
    id: 'cmd_inject_spawn_concat',
    name: 'Command Injection via spawn() with String Concatenation',
    language: LanguageType.JAVASCRIPT,
    type: VulnerabilityType.COMMAND_INJECTION,
    severity: SeverityLevel.HIGH,
    pattern: /spawn\s*\(\s*['"`][^'"`]*['"`]\s*,\s*\[[^\]]*\+[^\]]*\]\s*\)/g,
    description: 'Command injection through spawn() with concatenated arguments',
    examples: {
      vulnerable: [
        'spawn("sh", ["-c", "ls " + userDir])',
        'spawn("cat", [baseFile + userExtension])',
      ],
      safe: [
        'spawn("sh", ["-c", "ls"], { cwd: userDir })',
        'spawn("cat", [path.join(baseDir, userFile)])',
      ],
    },
    references: [
      'https://nodejs.org/api/child_process.html#child_processspawncommand-args-options',
    ],
    cweId: 'CWE-78',
    owaspCategory: 'A03:2021 – Injection',
  },

  {
    id: 'cmd_inject_child_process_exec',
    name: 'Child Process Execution with User Input',
    language: LanguageType.TYPESCRIPT,
    type: VulnerabilityType.COMMAND_INJECTION,
    severity: SeverityLevel.HIGH,
    pattern: /child_process\.exec\s*\(\s*['"`][^'"`]*['"`]\s*\+[^,)]+/g,
    description: 'Command injection through child_process.exec with string concatenation',
    examples: {
      vulnerable: [
        'child_process.exec("ls " + userDirectory)',
        'child_process.exec(`grep "${searchTerm}" file.txt`)',
      ],
      safe: [
        'child_process.execFile("ls", [userDirectory])',
        'child_process.spawn("grep", [searchTerm, "file.txt"])',
      ],
    },
    references: [
      'https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback',
    ],
    cweId: 'CWE-78',
    owaspCategory: 'A03:2021 – Injection',
  },

  {
    id: 'cmd_inject_eval_execution',
    name: 'Code Injection via eval() with User Input',
    language: LanguageType.JAVASCRIPT,
    type: VulnerabilityType.COMMAND_INJECTION,
    severity: SeverityLevel.CRITICAL,
    pattern: /eval\s*\(\s*['"`][^'"`]*['"`]\s*\+[^)]+\)|eval\s*\(\s*`[^`]*\$\{[^}]*\}[^`]*`\s*\)/g,
    description: 'Code injection through eval() function with user-controlled input',
    examples: {
      vulnerable: [
        'eval("const result = " + userCode)',
        'eval(`return ${userExpression}`)',
      ],
      safe: [
        'JSON.parse(userInput)',
        'Function("return " + sanitize(userExpression))()',
      ],
    },
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval',
      'https://cwe.mitre.org/data/definitions/94.html',
    ],
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021 – Injection',
  },

  {
    id: 'cmd_inject_python_subprocess',
    name: 'Python Subprocess Command Injection',
    language: LanguageType.PYTHON,
    type: VulnerabilityType.COMMAND_INJECTION,
    severity: SeverityLevel.HIGH,
    pattern: /subprocess\.(call|run|Popen)\s*\(\s*['"`][^'"`]*['"`]\s*[\+%]\s*\w+/g,
    description: 'Command injection in Python subprocess calls with string formatting',
    examples: {
      vulnerable: [
        'subprocess.call("ls " + user_dir)',
        'subprocess.run(f"cat {filename}")',
        'subprocess.Popen("rm " + file_path)',
      ],
      safe: [
        'subprocess.call(["ls", user_dir])',
        'subprocess.run(["cat", filename])',
        'subprocess.Popen(["rm", file_path])',
      ],
    },
    references: [
      'https://docs.python.org/3/library/subprocess.html#security-considerations',
    ],
    cweId: 'CWE-78',
    owaspCategory: 'A03:2021 – Injection',
  },

  {
    id: 'cmd_inject_shell_true',
    name: 'Subprocess with shell=True',
    language: LanguageType.PYTHON,
    type: VulnerabilityType.COMMAND_INJECTION,
    severity: SeverityLevel.MEDIUM,
    pattern: /subprocess\.\w+\([^)]*shell\s*=\s*True[^)]*\)/g,
    description: 'Use of shell=True in subprocess calls increases command injection risk',
    examples: {
      vulnerable: [
        'subprocess.call(command, shell=True)',
        'subprocess.run(f"ls {directory}", shell=True)',
      ],
      safe: [
        'subprocess.call(["ls", directory])',
        'subprocess.run(["ls", directory])',
      ],
    },
    references: [
      'https://docs.python.org/3/library/subprocess.html#security-considerations',
    ],
    cweId: 'CWE-78',
    owaspCategory: 'A03:2021 – Injection',
  },
];

export const commandInjectionDetector = new CommandInjectionDetector();
