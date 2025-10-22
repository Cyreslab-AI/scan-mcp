// Path traversal vulnerability detector
import { VulnerabilityDetector, DetectionContext, PatternMatcher, SecurityUtils } from './base';
import { Vulnerability, VulnerabilityPattern, PathTraversalVuln } from '@/types/vulnerability';
import { LanguageAST } from '@/types/language';
import { LanguageType, SeverityLevel, VulnerabilityType } from '@/types';

export class PathTraversalDetector extends VulnerabilityDetector {
  constructor() {
    const patterns = PATH_TRAVERSAL_PATTERNS;
    const supportedLanguages = [
      LanguageType.TYPESCRIPT,
      LanguageType.JAVASCRIPT,
      LanguageType.PYTHON,
    ];

    super(VulnerabilityType.PATH_TRAVERSAL, supportedLanguages, patterns);
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
        
        // Create enhanced path traversal vulnerability
        const pathTraversalVuln = this.createPathTraversalVuln(
          pattern, 
          ast.filePath, 
          position, 
          context, 
          match
        );

        vulnerabilities.push(pathTraversalVuln);
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
        nodeType: 'FileSystemAccess',
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

  private createPathTraversalVuln(
    pattern: VulnerabilityPattern,
    filePath: string,
    position: { line: number; column: number },
    context: DetectionContext,
    match: any
  ): PathTraversalVuln {
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
        pathMatch: match.match,
        traversalPattern: this.extractTraversalPattern(match.match),
      }
    );

    // Extract path traversal specific details
    const traversalDetails = this.analyzePathTraversal(match.match);

    return {
      ...baseVuln,
      type: VulnerabilityType.PATH_TRAVERSAL,
      path: traversalDetails.path,
      traversalPattern: traversalDetails.traversalPattern,
      accessLevel: traversalDetails.accessLevel,
      ...(traversalDetails.basePath && { basePath: traversalDetails.basePath }),
    };
  }

  private extractTraversalPattern(pathMatch: string): string {
    // Extract the traversal pattern used
    const traversalPatterns = [
      { pattern: /\.\.\//, sequence: '../' },
      { pattern: /\.\.\\/, sequence: '..\\' },
      { pattern: /\.\.%2[Ff]/, sequence: '..%2F' },
      { pattern: /\.\.%5[Cc]/, sequence: '..%5C' },
    ];

    for (const { pattern, sequence } of traversalPatterns) {
      if (pattern.test(pathMatch)) {
        return sequence;
      }
    }

    return 'Unknown traversal pattern';
  }

  private analyzePathTraversal(pathMatch: string): PathTraversalAnalysis {
    // Extract path details
    const path = this.extractFilePath(pathMatch);
    const traversalPattern = this.extractTraversalPattern(pathMatch);
    const basePath = this.extractBasePath(pathMatch);
    const accessLevel = this.determineAccessLevel(pathMatch);

    return {
      path,
      traversalPattern,
      accessLevel,
      ...(basePath && { basePath }),
    };
  }

  private extractFilePath(pathMatch: string): string {
    // Extract the file path being accessed
    const pathPatterns = [
      /['"`]([^'"`]+)['"`]/,
      /\$\{([^}]+)\}/,
      /\+\s*([a-zA-Z_$][a-zA-Z0-9_$]*)/,
    ];

    for (const pattern of pathPatterns) {
      const match = pathMatch.match(pattern);
      if (match && match[1]) {
        return match[1];
      }
    }

    return 'Unknown path';
  }

  private extractBasePath(pathMatch: string): string | undefined {
    // Extract base path if present
    const basePathPatterns = [
      /path\.join\s*\(\s*['"`]([^'"`]+)['"`]/,
      /basePath\s*\+/,
      /baseDir\s*\+/,
    ];

    for (const pattern of basePathPatterns) {
      const match = pathMatch.match(pattern);
      if (match) {
        return match[1] || 'basePath variable';
      }
    }

    return undefined;
  }

  private determineAccessLevel(pathMatch: string): 'read' | 'write' | 'execute' {
    // Determine the type of file system access
    if (/write|create|mkdir|append/i.test(pathMatch)) {
      return 'write';
    }

    if (/exec|spawn|run/i.test(pathMatch)) {
      return 'execute';
    }

    return 'read'; // Default assumption
  }
}

// Path traversal analysis result
interface PathTraversalAnalysis {
  path: string;
  traversalPattern: string;
  basePath?: string;
  accessLevel: 'read' | 'write' | 'execute';
}

// Path traversal patterns for different languages
const PATH_TRAVERSAL_PATTERNS: VulnerabilityPattern[] = [
  {
    id: 'path_traversal_dotdot_slash',
    name: 'Directory Traversal with ../ Sequences',
    language: LanguageType.TYPESCRIPT,
    type: VulnerabilityType.PATH_TRAVERSAL,
    severity: SeverityLevel.HIGH,
    pattern: /fs\.\w+\s*\(\s*['"`][^'"`]*\.\.[\/\\][^'"`]*['"`]/g,
    description: 'File system access using ../ or ..\\ sequences that can escape intended directories',
    examples: {
      vulnerable: [
        'fs.readFile("./files/../../../etc/passwd")',
        'fs.writeFile("../secret.txt", data)',
        'fs.readFileSync("uploads/../config/database.json")',
      ],
      safe: [
        'fs.readFile(path.join(safeDir, path.basename(filename)))',
        'fs.writeFile(path.resolve(uploadsDir, sanitize(filename)), data)',
      ],
    },
    references: [
      'https://owasp.org/www-community/attacks/Path_Traversal',
      'https://cwe.mitre.org/data/definitions/22.html',
    ],
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021 – Broken Access Control',
  },

  {
    id: 'path_traversal_concatenation',
    name: 'Path Concatenation without Validation',
    language: LanguageType.JAVASCRIPT,
    type: VulnerabilityType.PATH_TRAVERSAL,
    severity: SeverityLevel.HIGH,
    pattern: /fs\.\w+\s*\(\s*[^,)]*\+\s*[a-zA-Z_$][a-zA-Z0-9_$]*[^,)]*\)/g,
    description: 'File path construction using string concatenation without proper validation',
    examples: {
      vulnerable: [
        'fs.readFile(baseDir + "/" + userFile)',
        'fs.writeFile(uploadPath + filename, data)',
      ],
      safe: [
        'fs.readFile(path.join(baseDir, path.basename(userFile)))',
        'fs.writeFile(path.resolve(uploadPath, sanitize(filename)), data)',
      ],
    },
    references: [
      'https://nodejs.org/api/fs.html',
    ],
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021 – Broken Access Control',
  },

  {
    id: 'path_traversal_template_literal',
    name: 'Path Traversal via Template Literals',
    language: LanguageType.TYPESCRIPT,
    type: VulnerabilityType.PATH_TRAVERSAL,
    severity: SeverityLevel.HIGH,
    pattern: /fs\.\w+\s*\(\s*`[^`]*\$\{[^}]*\}[^`]*`/g,
    description: 'File paths constructed with template literals without validation',
    examples: {
      vulnerable: [
        'fs.readFile(`./uploads/${userFile}`)',
        'fs.writeFile(`./data/${category}/${filename}`, content)',
      ],
      safe: [
        'fs.readFile(path.join("./uploads", path.basename(userFile)))',
        'fs.writeFile(path.join("./data", sanitize(category), sanitize(filename)), content)',
      ],
    },
    references: [
      'https://nodejs.org/api/path.html#path_path_basename_path_ext',
    ],
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021 – Broken Access Control',
  },

  {
    id: 'path_traversal_python_open',
    name: 'Python File Access Path Traversal',
    language: LanguageType.PYTHON,
    type: VulnerabilityType.PATH_TRAVERSAL,
    severity: SeverityLevel.HIGH,
    pattern: /open\s*\(\s*['"`][^'"`]*\.\.[\/\\][^'"`]*['"`]|open\s*\(\s*[^,)]*\+\s*\w+/g,
    description: 'File access in Python with path traversal sequences or unsafe concatenation',
    examples: {
      vulnerable: [
        'open("../../../etc/passwd", "r")',
        'open(base_path + "/" + user_file, "w")',
        'open(f"./uploads/{user_filename}", "r")',
      ],
      safe: [
        'open(os.path.join(safe_dir, os.path.basename(user_file)), "r")',
        'open(os.path.abspath(os.path.join(base_path, secure_filename)), "w")',
      ],
    },
    references: [
      'https://docs.python.org/3/library/os.path.html#os.path.basename',
    ],
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021 – Broken Access Control',
  },

  {
    id: 'path_traversal_url_encoded',
    name: 'URL-Encoded Path Traversal Sequences',
    language: LanguageType.TYPESCRIPT,
    type: VulnerabilityType.PATH_TRAVERSAL,
    severity: SeverityLevel.MEDIUM,
    pattern: /\.\.%2[Ff]|\.\.%5[Cc]/gi,
    description: 'URL-encoded path traversal sequences that bypass basic filtering',
    examples: {
      vulnerable: [
        'fs.readFile(decodeURIComponent("..%2F..%2Fetc%2Fpasswd"))',
        'res.sendFile(req.query.file) // where file=..%2F..%2Fsecret.txt',
      ],
      safe: [
        'fs.readFile(path.resolve(safeDir, path.basename(decodeURIComponent(filename))))',
        'res.sendFile(path.join(publicDir, sanitizePath(req.query.file)))',
      ],
    },
    references: [
      'https://owasp.org/www-community/attacks/Path_Traversal',
    ],
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021 – Broken Access Control',
  },
];

export const pathTraversalDetector = new PathTraversalDetector();

// Path traversal analysis result
interface PathTraversalAnalysis {
  path: string;
  traversalPattern: string;
  basePath?: string;
  accessLevel: 'read' | 'write' | 'execute';
}
