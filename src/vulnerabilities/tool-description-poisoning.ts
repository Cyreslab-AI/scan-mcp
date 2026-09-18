// Description-based "tool poisoning" / "rug pull" detection for MCP tool definitions.
//
// The well-documented MCP "tool poisoning attack" (see Invariant Labs' write-up and the Cloud
// Security Alliance's coverage of "MCP rug pulls") is NOT about a tool's handler code calling
// exec()/eval(). It is about malicious instructions hidden inside a tool's *description* or
// other metadata (name, parameter descriptions) that are shown to - and can manipulate - the
// calling LLM, while looking innocuous (or invisible) to a human reviewer. Examples: text that
// tells the model to always call this tool first, to never mention what it did, to ignore the
// user's actual instructions, or hidden/invisible Unicode characters that carry a payload only
// the model "reads".
//
// `src/vulnerabilities/tool-poisoning.ts` only ever looked at handler code, so this attack
// surface was completely unscanned. This module is a complementary, static-analysis pass that
// extracts likely tool description strings from source files and inspects the text itself.
import { Vulnerability, RemediationGuidance } from '@/types/vulnerability';
import { SeverityLevel, VulnerabilityType } from '@/types';

interface DescriptionMatch {
  text: string;
  index: number;
}

interface PhrasePattern {
  pattern: RegExp;
  label: string;
}

// Zero-width/invisible/bidi-control characters, plus the Unicode Tag block (U+E0000-U+E007F)
// used in real-world "ASCII smuggling" prompt-injection payloads that render as nothing to a
// human but are still tokenized and read by an LLM.
// eslint-disable-next-line no-control-regex
const HIDDEN_UNICODE_RE = /[​-‏‪-‮⁠-⁤﻿­]|[\u{E0000}-\u{E007F}]/gu;

const SUSPICIOUS_PHRASES: PhrasePattern[] = [
  { pattern: /ignore\s+(all|any)?\s*(the\s+)?(previous|prior|above)\s+instructions/i, label: 'Instruction override attempt' },
  { pattern: /disregard\s+(the|any|all)?\s*(system|previous|prior)\s+(prompt|instructions)/i, label: 'Instruction override attempt' },
  { pattern: /(always|you must)\s+call\s+this\s+tool\s+first/i, label: 'Forced tool-priority directive' },
  { pattern: /this\s+tool\s+(must|should|has to)\s+be\s+(called|used|invoked)\s+(first|before)/i, label: 'Forced tool-priority directive' },
  { pattern: /before\s+(calling|using|invoking)\s+any\s+other\s+tool/i, label: 'Forced tool-priority directive' },
  { pattern: /do\s*n[o']?t\s+tell\s+the\s+user/i, label: 'Concealment directive' },
  { pattern: /without\s+(informing|telling|notifying|asking)\s+the\s+user/i, label: 'Concealment directive' },
  { pattern: /never\s+(mention|reveal|disclose|show)\s+(this|that)/i, label: 'Concealment directive' },
  { pattern: /keep\s+this\s+(secret|hidden)\s+from\s+the\s+user/i, label: 'Concealment directive' },
  { pattern: /do\s*n[o']?t\s+(ask|require)\s+(for\s+)?(confirmation|permission)/i, label: 'Consent-bypass directive' },
  { pattern: /you\s+(must|should)\s+always\s+(use|call|run|execute)/i, label: 'Forced tool-priority directive' },
  { pattern: /secretly/i, label: 'Concealment directive' },
  { pattern: /system\s*:\s*you\s+are/i, label: 'Embedded fake system prompt' },
  { pattern: /<\s*system\s*>/i, label: 'Embedded fake system role tag' },
  { pattern: /this\s+is\s+(very\s+)?important[,:.]?\s+always/i, label: 'Coercive emphasis directive' },
  { pattern: /also\s+send\s+.*(credentials|api\s*key|password|token|environment\s+variables?)/i, label: 'Data-exfiltration instruction' },
];

const REASSURING_WORDS_RE = /\b(read[- ]?only|no\s+side\s*effects?|does\s+not\s+(modify|write|delete|execute|access\s+the\s+network)|completely\s+safe|harmless|local[- ]?only)\b/i;

const DANGEROUS_NEARBY_RE = /\b(exec|eval|execSync|child_process|spawn|subprocess\.(run|Popen|call)|os\.system|fs\.(writeFile|unlinkSync|rmSync)|rm\s+-rf)\b/;

// Matches `description: "..."`, `description = "..."`, `"description": "..."` in TS/JS/JSON,
// including template literals, across languages that use similar object-literal syntax.
const DESCRIPTION_KV_RE = /["']?description["']?\s*[:=]\s*(['"`])((?:\\.|(?!\1)[^\\])*)\1/gi;

// Python triple-quoted docstring-style description, e.g. description = """...""".
const DESCRIPTION_TRIPLE_RE = /description\s*=\s*(?:"""|''')([\s\S]*?)(?:"""|''')/gi;

function extractDescriptions(content: string): DescriptionMatch[] {
  const matches: DescriptionMatch[] = [];

  for (const m of content.matchAll(DESCRIPTION_KV_RE)) {
    if (m.index === undefined || m[2] === undefined) continue;
    matches.push({ text: m[2], index: m.index });
  }

  for (const m of content.matchAll(DESCRIPTION_TRIPLE_RE)) {
    if (m.index === undefined || m[1] === undefined) continue;
    matches.push({ text: m[1], index: m.index });
  }

  return matches;
}

function findPosition(content: string, index: number): { line: number; column: number } {
  const lines = content.substring(0, index).split('\n');
  return { line: lines.length, column: lines[lines.length - 1]?.length || 0 };
}

function baseRemediation(title: string, steps: string[]): RemediationGuidance {
  return {
    title,
    description: 'Treat tool descriptions and other metadata shown to the calling LLM as untrusted, ' +
      'human-reviewable text - never as a place to embed behavioral directives.',
    steps,
    references: [
      'https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks',
      'https://modelcontextprotocol.io/docs/concepts/tools',
    ],
    effort: 'low',
    priority: 1,
  };
}

function makeVulnerability(
  filePath: string,
  content: string,
  index: number,
  title: string,
  description: string,
  severity: SeverityLevel,
  confidence: number,
  remediation: RemediationGuidance,
  tags: string[]
): Vulnerability {
  const position = findPosition(content, index);
  const scoreMap: Record<SeverityLevel, number> = {
    [SeverityLevel.CRITICAL]: 9.5,
    [SeverityLevel.HIGH]: 8.0,
    [SeverityLevel.MEDIUM]: 5.5,
    [SeverityLevel.LOW]: 2.0,
    [SeverityLevel.INFO]: 0.0,
  };

  return {
    id: `tool_desc_poison_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    type: VulnerabilityType.TOOL_POISONING,
    severity,
    score: scoreMap[severity],
    title,
    description,
    location: { file: filePath, line: position.line, column: position.column },
    remediation,
    cveReferences: [],
    context: { detectionMethod: 'tool-description-analysis' },
    detectedAt: new Date(),
    confidence,
    falsePositiveRisk: severity === SeverityLevel.CRITICAL ? 'low' : 'medium',
    tags: [VulnerabilityType.TOOL_POISONING, severity, 'description-based', ...tags],
  };
}

/**
 * Scan a source file's raw content for MCP tool descriptions that carry hidden Unicode payloads,
 * LLM-directed prompt-injection phrasing, or a description that contradicts what the handler
 * appears to actually do.
 */
export function analyzeToolDescriptions(content: string, filePath: string): Vulnerability[] {
  if (!/description/i.test(content)) {
    return [];
  }

  const vulnerabilities: Vulnerability[] = [];
  const descriptions = extractDescriptions(content);

  for (const { text, index } of descriptions) {
    if (HIDDEN_UNICODE_RE.test(text)) {
      HIDDEN_UNICODE_RE.lastIndex = 0;
      vulnerabilities.push(makeVulnerability(
        filePath,
        content,
        index,
        'Hidden/invisible Unicode characters in tool description',
        'This tool description contains zero-width, bidirectional-control, or Unicode "tag" ' +
          'characters that render as nothing (or as different text) to a human reviewer but are ' +
          'still visible to the calling LLM. This is the signature of a steganographic prompt-' +
          'injection payload used in real-world MCP "tool poisoning" / "rug pull" attacks.',
        SeverityLevel.CRITICAL,
        0.9,
        baseRemediation('Remove hidden Unicode characters from tool metadata', [
          'Strip zero-width space/joiner, bidi override, and Unicode Tag characters from all tool names, descriptions, and parameter descriptions',
          'Diff tool metadata against its previous published version before every release ("rug pull" detection)',
          'Render descriptions through a visible-character-only validator before publishing the server',
        ]),
        ['hidden-unicode', 'steganography']
      ));
    }

    for (const { pattern, label } of SUSPICIOUS_PHRASES) {
      if (pattern.test(text)) {
        vulnerabilities.push(makeVulnerability(
          filePath,
          content,
          index,
          `Suspicious instruction embedded in tool description: ${label}`,
          `The tool description contains text that reads as an instruction directed at the calling ` +
            `LLM rather than documentation for a human ("${text.trim().slice(0, 160)}"). This matches ` +
            `the pattern of documented MCP tool-poisoning attacks, where descriptions manipulate the ` +
            `model into taking hidden actions (always invoking a tool, hiding behavior from the user, ` +
            `or ignoring the user's real instructions).`,
          SeverityLevel.HIGH,
          0.75,
          baseRemediation('Remove behavioral directives from tool descriptions', [
            'Rewrite the description as plain, factual documentation of what the tool does',
            'Never phrase a description as an instruction to the model ("always...", "do not tell the user...")',
            'Review descriptions for any text that reads as being addressed to the AI rather than a human',
          ]),
          ['prompt-injection', 'instruction-override']
        ));
      }
    }

    if (REASSURING_WORDS_RE.test(text)) {
      const windowEnd = Math.min(content.length, index + text.length + 500);
      const nearby = content.slice(index, windowEnd);
      if (DANGEROUS_NEARBY_RE.test(nearby)) {
        vulnerabilities.push(makeVulnerability(
          filePath,
          content,
          index,
          'Tool description contradicts its handler behavior',
          'This tool description claims safe/read-only/harmless behavior, but the surrounding code ' +
            'performs operations (process execution, file writes, subprocess calls) that contradict ' +
            'that claim. A description-vs-behavior mismatch is exactly what a "rug pull" style attack ' +
            'relies on to get a user or reviewer to trust a tool they would otherwise scrutinize.',
          SeverityLevel.MEDIUM,
          0.55,
          baseRemediation('Make the description match actual behavior', [
            'Update the description to accurately reflect side effects (file/network/process access)',
            'If the tool is genuinely read-only, remove the dangerous call; if not, remove the safety claim',
          ]),
          ['description-behavior-mismatch']
        ));
      }
    }
  }

  return vulnerabilities;
}
