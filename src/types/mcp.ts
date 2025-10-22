// MCP (Model Context Protocol) types for security scanning
import { SeverityLevel } from './index';

export interface McpServerConfig {
  name: string;
  command: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
  transport: McpTransport;
  timeout?: number;
  retries?: number;
}

export interface McpTransport {
  type: 'stdio' | 'http';
  config: StdioTransportConfig | HttpTransportConfig;
}

export interface StdioTransportConfig {
  // No additional configuration needed for stdio
}

export interface HttpTransportConfig {
  url: string;
  headers?: Record<string, string>;
  timeout?: number;
  retries?: number;
  auth?: McpAuth;
}

export interface McpAuth {
  type: 'basic' | 'bearer' | 'oauth2' | 'apikey';
  credentials: BasicAuth | BearerAuth | OAuth2Auth | ApiKeyAuth;
}

export interface BasicAuth {
  username: string;
  password: string;
}

export interface BearerAuth {
  token: string;
}

export interface OAuth2Auth {
  clientId: string;
  clientSecret?: string;
  scope?: string[];
  tokenEndpoint: string;
  authEndpoint?: string;
  redirectUri?: string;
  grantType: 'authorization_code' | 'client_credentials' | 'implicit';
}

export interface ApiKeyAuth {
  key: string;
  header?: string; // Default: 'X-API-Key'
  query?: string; // Alternative to header
}

// MCP Protocol Message Types
export interface McpRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: Record<string, unknown> | unknown[];
}

export interface McpResponse {
  jsonrpc: '2.0';
  id: string | number;
  result?: unknown;
  error?: McpError;
}

export interface McpNotification {
  jsonrpc: '2.0';
  method: string;
  params?: Record<string, unknown> | unknown[];
}

export interface McpError {
  code: number;
  message: string;
  data?: unknown;
}

// MCP Capability Types
export interface McpCapabilities {
  tools?: McpToolCapability;
  resources?: McpResourceCapability;
  prompts?: McpPromptCapability;
  logging?: McpLoggingCapability;
}

export interface McpToolCapability {
  listChanged?: boolean;
}

export interface McpResourceCapability {
  subscribe?: boolean;
  listChanged?: boolean;
}

export interface McpPromptCapability {
  listChanged?: boolean;
}

export interface McpLoggingCapability {
  // No additional properties
}

// MCP Tool Types
export interface McpTool {
  name: string;
  description?: string;
  inputSchema: McpToolInputSchema;
}

export interface McpToolInputSchema {
  type: 'object';
  properties?: Record<string, McpSchemaProperty>;
  required?: string[];
  additionalProperties?: boolean;
}

export interface McpSchemaProperty {
  type: string;
  description?: string;
  enum?: unknown[];
  items?: McpSchemaProperty;
  properties?: Record<string, McpSchemaProperty>;
  required?: string[];
  default?: unknown;
  pattern?: string;
  format?: string;
  minimum?: number;
  maximum?: number;
}

export interface McpToolCall {
  name: string;
  arguments: Record<string, unknown>;
}

export interface McpToolResult {
  content: McpContent[];
  isError?: boolean;
}

export interface McpContent {
  type: 'text' | 'image' | 'resource';
  text?: string;
  data?: string;
  mimeType?: string;
  annotations?: McpAnnotation;
}

export interface McpAnnotation {
  audience?: 'user' | 'assistant';
  priority?: number;
}

// MCP Resource Types
export interface McpResource {
  uri: string;
  name: string;
  description?: string;
  mimeType?: string;
}

export interface McpResourceContents {
  uri: string;
  mimeType?: string;
  text?: string;
  blob?: string; // base64 encoded
}

// MCP Prompt Types
export interface McpPrompt {
  name: string;
  description?: string;
  arguments?: McpPromptArgument[];
}

export interface McpPromptArgument {
  name: string;
  description?: string;
  required?: boolean;
}

export interface McpPromptMessage {
  role: 'user' | 'assistant' | 'system';
  content: McpContent[];
}

export interface McpGetPromptRequest {
  name: string;
  arguments?: Record<string, string>;
}

export interface McpGetPromptResult {
  description?: string;
  messages: McpPromptMessage[];
}

// Security-specific MCP types
export interface McpSecurityContext {
  serverId: string;
  serverPath: string;
  capabilities: McpCapabilities;
  tools: McpToolSecurity[];
  resources: McpResourceSecurity[];
  prompts: McpPromptSecurity[];
  riskScore: number;
  threats: McpThreat[];
}

export interface McpToolSecurity {
  tool: McpTool;
  riskLevel: SeverityLevel;
  dangerousOperations: string[];
  inputValidation: InputValidationRule[];
  outputSanitization: OutputSanitizationRule[];
  accessControl: AccessControlRule[];
}

export interface McpResourceSecurity {
  resource: McpResource;
  riskLevel: SeverityLevel;
  accessPattern: 'read' | 'write' | 'execute';
  sensitiveData: boolean;
  pathTraversalRisk: boolean;
  accessControl: AccessControlRule[];
}

export interface McpPromptSecurity {
  prompt: McpPrompt;
  riskLevel: SeverityLevel;
  injectionVectors: string[];
  manipulationRisk: boolean;
  dataExfiltrationRisk: boolean;
}

export interface McpThreat {
  id: string;
  type: 'tool_poisoning' | 'prompt_injection' | 'data_exfiltration' | 'privilege_escalation';
  severity: SeverityLevel;
  description: string;
  vector: string;
  impact: string;
  likelihood: number; // 0-1
  mitigation?: string[];
}

export interface InputValidationRule {
  parameter: string;
  rules: ValidationConstraint[];
  sanitization: SanitizationRule[];
}

export interface ValidationConstraint {
  type: 'type' | 'pattern' | 'range' | 'length' | 'enum' | 'custom';
  value: unknown;
  message?: string;
}

export interface SanitizationRule {
  type: 'escape' | 'filter' | 'transform' | 'validate';
  config: Record<string, unknown>;
}

export interface OutputSanitizationRule {
  field: string;
  rules: SanitizationRule[];
}

export interface AccessControlRule {
  resource: string;
  permissions: Permission[];
  conditions?: AccessCondition[];
}

export interface Permission {
  action: string;
  allowed: boolean;
  restrictions?: Record<string, unknown>;
}

export interface AccessCondition {
  type: 'time' | 'location' | 'user' | 'context' | 'rate_limit';
  config: Record<string, unknown>;
}

// MCP Connection and Session Management
export interface McpConnection {
  id: string;
  serverConfig: McpServerConfig;
  status: 'connecting' | 'connected' | 'disconnected' | 'error';
  capabilities: McpCapabilities;
  lastActivity: Date;
  metrics: ConnectionMetrics;
  securityContext: McpSecurityContext;
}

export interface ConnectionMetrics {
  requestCount: number;
  errorCount: number;
  averageResponseTime: number;
  bytesSent: number;
  bytesReceived: number;
  uptime: number;
}

export interface McpSession {
  id: string;
  connections: McpConnection[];
  startTime: Date;
  user?: string;
  context: Record<string, unknown>;
  auditLog: AuditLogEntry[];
}

export interface AuditLogEntry {
  timestamp: Date;
  connectionId: string;
  operation: string;
  parameters?: Record<string, unknown>;
  result?: 'success' | 'error' | 'timeout';
  securityEvent?: boolean;
  riskScore?: number;
}
