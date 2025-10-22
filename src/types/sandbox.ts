// Sandbox environment types for secure dynamic analysis
export interface SandboxEnvironment {
  id: string;
  type: 'docker' | 'vm2' | 'native';
  config: SandboxConfig;
  status: SandboxStatus;
  limits: ResourceLimits;
  isolation: IsolationConfig;
  monitoring: MonitoringConfig;
}

export interface SandboxConfig {
  image?: string; // Docker image for container sandboxes
  baseDir: string;
  workingDir: string;
  timeout: number; // in milliseconds
  cleanup: boolean;
  persistent: boolean;
  networking: NetworkConfig;
  fileSystem: FileSystemConfig;
  environment: Record<string, string>;
}

export interface SandboxStatus {
  state: 'creating' | 'ready' | 'running' | 'stopped' | 'error' | 'destroyed';
  startTime?: Date;
  endTime?: Date;
  pid?: number;
  containerId?: string;
  lastActivity: Date;
  errorMessage?: string;
}

export interface ResourceLimits {
  memory: string; // e.g., '512m', '1g'
  cpu: string; // e.g., '0.5', '1.0'
  disk: string; // e.g., '100m', '1g'
  networkBandwidth?: string;
  maxProcesses?: number;
  maxFiles?: number;
  maxSockets?: number;
}

export interface IsolationConfig {
  networkIsolation: boolean;
  fileSystemIsolation: boolean;
  processIsolation: boolean;
  userNamespace: boolean;
  capabilities: string[];
  seccompProfile?: string;
  apparmorProfile?: string;
}

export interface MonitoringConfig {
  enableResourceMonitoring: boolean;
  enableNetworkMonitoring: boolean;
  enableFileSystemMonitoring: boolean;
  enableProcessMonitoring: boolean;
  monitoringInterval: number; // in milliseconds
  alertThresholds: AlertThresholds;
}

export interface AlertThresholds {
  memoryUsage: number; // percentage
  cpuUsage: number; // percentage
  diskUsage: number; // percentage
  networkConnections: number;
  suspiciousActivity: boolean;
}

export interface NetworkConfig {
  enabled: boolean;
  mode: 'none' | 'bridge' | 'host' | 'custom';
  allowedHosts?: string[];
  blockedHosts?: string[];
  allowedPorts?: number[];
  blockedPorts?: number[];
  proxyConfig?: ProxyConfig;
}

export interface ProxyConfig {
  http?: string;
  https?: string;
  socks?: string;
  noProxy?: string[];
}

export interface FileSystemConfig {
  readOnlyPaths: string[];
  writablePaths: string[];
  mountPoints: MountPoint[];
  tempDir: string;
  maxFileSize: string;
  allowedExtensions?: string[];
  blockedExtensions?: string[];
}

export interface MountPoint {
  source: string;
  destination: string;
  readOnly: boolean;
  type?: 'bind' | 'volume' | 'tmpfs';
}

export interface SandboxExecution {
  id: string;
  sandboxId: string;
  command: string;
  args: string[];
  workingDir?: string;
  env?: Record<string, string>;
  input?: string;
  timeout?: number;
  status: ExecutionStatus;
  result?: ExecutionResult;
  startTime: Date;
  endTime?: Date;
}

export interface ExecutionStatus {
  state: 'queued' | 'running' | 'completed' | 'failed' | 'timeout' | 'cancelled';
  progress?: number; // 0-100
  message?: string;
}

export interface ExecutionResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  duration: number; // in milliseconds
  resources: ResourceUsage;
  monitoring: ExecutionMonitoring;
  securityEvents: SecurityEvent[];
}

export interface ResourceUsage {
  maxMemory: number; // in bytes
  avgMemory: number;
  maxCpu: number; // percentage
  avgCpu: number;
  diskRead: number; // in bytes
  diskWrite: number;
  networkSent: number;
  networkReceived: number;
}

export interface ExecutionMonitoring {
  systemCalls: SystemCall[];
  fileOperations: FileOperation[];
  networkConnections: NetworkConnection[];
  processTree: ProcessInfo[];
  environmentChanges: EnvironmentChange[];
}

export interface SystemCall {
  name: string;
  args: unknown[];
  result: unknown;
  timestamp: Date;
  duration: number; // in microseconds
  suspicious: boolean;
}

export interface FileOperation {
  operation: 'open' | 'read' | 'write' | 'create' | 'delete' | 'rename' | 'chmod';
  path: string;
  flags?: string[];
  mode?: string;
  size?: number;
  timestamp: Date;
  allowed: boolean;
  suspicious: boolean;
}

export interface NetworkConnection {
  protocol: 'tcp' | 'udp' | 'icmp';
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  state: 'established' | 'listen' | 'closed' | 'syn_sent' | 'syn_recv';
  timestamp: Date;
  dataTransferred: number;
  allowed: boolean;
  suspicious: boolean;
}

export interface ProcessInfo {
  pid: number;
  ppid: number;
  name: string;
  command: string;
  args: string[];
  user: string;
  startTime: Date;
  endTime?: Date;
  exitCode?: number;
  resources: ResourceUsage;
}

export interface EnvironmentChange {
  type: 'variable' | 'path' | 'user' | 'group' | 'permissions';
  before: unknown;
  after: unknown;
  timestamp: Date;
  suspicious: boolean;
}

export interface SecurityEvent {
  type: 'privilege_escalation' | 'suspicious_syscall' | 'network_violation' | 'file_violation' | 'resource_limit' | 'malicious_behavior';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  details: Record<string, unknown>;
  timestamp: Date;
  confidence: number; // 0-1
  mitigated: boolean;
}

// Docker-specific types
export interface DockerSandboxConfig extends SandboxConfig {
  image: string;
  dockerfile?: string;
  buildContext?: string;
  registry?: DockerRegistry;
  volumes: DockerVolume[];
  ports: DockerPort[];
  labels: Record<string, string>;
  entrypoint?: string[];
  cmd?: string[];
}

export interface DockerRegistry {
  url: string;
  username?: string;
  password?: string;
  token?: string;
}

export interface DockerVolume {
  name?: string;
  source: string;
  destination: string;
  readOnly: boolean;
  type: 'bind' | 'volume' | 'tmpfs';
}

export interface DockerPort {
  containerPort: number;
  hostPort?: number;
  protocol: 'tcp' | 'udp';
}

export interface DockerContainer {
  id: string;
  name: string;
  image: string;
  status: string;
  state: string;
  created: Date;
  started?: Date;
  finished?: Date;
  ports: DockerPort[];
  mounts: DockerVolume[];
  networkSettings: DockerNetworkSettings;
  logs: string[];
}

export interface DockerNetworkSettings {
  bridge?: string;
  sandboxId?: string;
  hairpinMode?: boolean;
  linkLocalIPv6Address?: string;
  linkLocalIPv6PrefixLen?: number;
  sandboxKey?: string;
  secondaryIPAddresses?: string[];
  secondaryIPv6Addresses?: string[];
  endpointId?: string;
  gateway?: string;
  globalIPv6Address?: string;
  globalIPv6PrefixLen?: number;
  ipAddress?: string;
  ipPrefixLen?: number;
  ipv6Gateway?: string;
  macAddress?: string;
  networks?: Record<string, DockerNetworkInfo>;
}

export interface DockerNetworkInfo {
  networkId: string;
  endpointId: string;
  gateway: string;
  ipAddress: string;
  ipPrefixLen: number;
  ipv6Gateway: string;
  globalIPv6Address: string;
  globalIPv6PrefixLen: number;
  macAddress: string;
}

// VM2-specific types
export interface VM2SandboxConfig extends SandboxConfig {
  sandbox: VM2Context;
  eval: boolean;
  wasm: boolean;
  fixAsync: boolean;
  allowAsync: boolean;
}

export interface VM2Context {
  [key: string]: unknown;
}

// Sandbox management types
export interface SandboxManager {
  createSandbox(config: SandboxConfig): Promise<SandboxEnvironment>;
  destroySandbox(sandboxId: string): Promise<void>;
  execute(sandboxId: string, execution: SandboxExecution): Promise<ExecutionResult>;
  monitor(sandboxId: string): Promise<ExecutionMonitoring>;
  listSandboxes(): Promise<SandboxEnvironment[]>;
  getSandboxStatus(sandboxId: string): Promise<SandboxStatus>;
  cleanupSandboxes(): Promise<void>;
}

export interface SandboxPool {
  maxSize: number;
  currentSize: number;
  available: SandboxEnvironment[];
  busy: SandboxEnvironment[];
  config: SandboxPoolConfig;
}

export interface SandboxPoolConfig {
  preAllocate: number;
  maxIdle: number;
  idleTimeout: number; // in milliseconds
  maxLifetime: number; // in milliseconds
  healthCheck: boolean;
  healthCheckInterval: number; // in milliseconds
}
