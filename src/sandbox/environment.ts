// Secure sandbox environment for dynamic MCP security analysis
import Docker from 'dockerode';
import * as path from 'path';
import { 
  SandboxEnvironment,
  SandboxConfig,
  SandboxExecution,
  ExecutionResult,
  DockerSandboxConfig,
  SandboxManager,
  SecurityEvent,
  ExecutionMonitoring
} from '@/types/sandbox';

export class DockerSandboxEnvironment {
  readonly id: string;
  readonly type = 'docker' as const;
  public config: SandboxConfig;
  public status: any;
  public limits: any;
  public isolation: any;
  public monitoring: any;

  private docker: Docker;
  private container: Docker.Container | null = null;

  constructor(config: SandboxConfig) {
    this.id = this.generateSandboxId();
    this.config = config;
    this.docker = new Docker();
    
    this.status = {
      state: 'creating',
      lastActivity: new Date(),
    };

    this.limits = {
      memory: config.environment?.['MEMORY_LIMIT'] || '512m',
      cpu: config.environment?.['CPU_LIMIT'] || '0.5',
      disk: '100m',
    };

    this.isolation = {
      networkIsolation: true,
      fileSystemIsolation: true,
      processIsolation: true,
      userNamespace: true,
      capabilities: ['SYS_ADMIN'], // Minimal capabilities
    };

    this.monitoring = {
      enableResourceMonitoring: true,
      enableNetworkMonitoring: true,
      enableFileSystemMonitoring: true,
      enableProcessMonitoring: true,
      monitoringInterval: 1000,
      alertThresholds: {
        memoryUsage: 80,
        cpuUsage: 80,
        diskUsage: 80,
        networkConnections: 10,
        suspiciousActivity: true,
      },
    };
  }

  async create(): Promise<void> {
    this.status.state = 'creating';
    
    try {
      const dockerConfig = this.buildDockerConfig();
      
      // Pull the base image if not available
      await this.ensureBaseImage(dockerConfig.image);
      
      // Create the container
      this.container = await this.docker.createContainer({
        Image: dockerConfig.image,
        WorkingDir: dockerConfig.workingDir,
        Env: Object.entries(dockerConfig.environment).map(([key, value]) => `${key}=${value}`),
        HostConfig: {
          Memory: this.parseMemoryLimit(this.limits.memory),
          CpuQuota: this.parseCpuLimit(this.limits.cpu),
          NetworkMode: this.config.networking.enabled ? 'bridge' : 'none',
          ReadonlyRootfs: true,
          SecurityOpt: ['no-new-privileges:true'],
          CapDrop: ['ALL'],
          CapAdd: this.isolation.capabilities,
          Tmpfs: {
            '/tmp': 'rw,size=100m,noexec,nosuid,nodev',
            '/var/tmp': 'rw,size=50m,noexec,nosuid,nodev',
          },
        },
        NetworkingConfig: {
          EndpointsConfig: {},
        },
      });

      this.status.state = 'ready';
      this.status.startTime = new Date();
      this.status.containerId = this.container.id;

    } catch (error) {
      this.status.state = 'error';
      this.status.errorMessage = error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`Failed to create sandbox: ${this.status.errorMessage}`);
    }
  }

  async execute(execution: SandboxExecution): Promise<ExecutionResult> {
    if (!this.container || this.status.state !== 'ready') {
      throw new Error('Sandbox not ready for execution');
    }

    execution.status = { state: 'running' };
    execution.startTime = new Date();

    try {
      // Start the container if not running
      await this.container.start();
      
      // Execute the command
      const exec = await this.container.exec({
        Cmd: [execution.command, ...execution.args],
        AttachStdout: true,
        AttachStderr: true,
        AttachStdin: !!execution.input,
        WorkingDir: execution.workingDir || this.config.workingDir,
        Env: execution.env ? Object.entries(execution.env).map(([k, v]) => `${k}=${v}`) : undefined,
      });

      const stream = await exec.start({ hijack: true, stdin: !!execution.input });
      
      if (execution.input) {
        stream.write(execution.input);
        stream.end();
      }

      // Collect output with timeout
      const result = await this.collectExecutionOutput(stream, execution.timeout || this.config.timeout);
      
      // Get execution inspection data (for future use)
      await exec.inspect();
      
      execution.status.state = 'completed';
      execution.endTime = new Date();
      execution.result = result;

      return result;

    } catch (error) {
      execution.status.state = 'failed';
      execution.status.message = error instanceof Error ? error.message : 'Execution failed';
      execution.endTime = new Date();
      
      throw error;
    }
  }

  async destroy(): Promise<void> {
    if (this.container) {
      try {
        // Stop the container
        await this.container.stop({ t: 5 });
        
        // Remove the container
        await this.container.remove({ force: true });
        
        this.status.state = 'destroyed';
        this.status.endTime = new Date();
      } catch (error) {
        this.status.state = 'error';
        this.status.errorMessage = error instanceof Error ? error.message : 'Cleanup error';
      }
    }
  }

  async getStatus(): Promise<any> {
    return this.status;
  }

  async monitor(): Promise<ExecutionMonitoring> {
    if (!this.container) {
      throw new Error('No container to monitor');
    }

    const stats = await this.container.stats({ stream: false });
    
    return {
      systemCalls: [], // TODO: Implement syscall monitoring
      fileOperations: [], // TODO: Implement file operation monitoring
      networkConnections: [], // TODO: Implement network monitoring
      processTree: [], // TODO: Implement process tree monitoring
      environmentChanges: [], // TODO: Implement environment change detection
    };
  }

  private buildDockerConfig(): DockerSandboxConfig {
    const dockerConfig = this.config as DockerSandboxConfig;
    
    return {
      ...dockerConfig,
      image: dockerConfig.image || 'node:18-alpine',
      volumes: dockerConfig.volumes || [],
      ports: dockerConfig.ports || [],
      labels: {
        'mcp-scanner': 'true',
        'sandbox-id': this.id,
        'created-at': new Date().toISOString(),
        ...dockerConfig.labels,
      },
    };
  }

  private async ensureBaseImage(imageName: string): Promise<void> {
    try {
      await this.docker.getImage(imageName).inspect();
    } catch {
      // Image doesn't exist, pull it
      await new Promise((resolve, reject) => {
        this.docker.pull(imageName, (err: any, stream: any) => {
          if (err) {
            reject(err);
            return;
          }
          
          this.docker.modem.followProgress(stream, (pullErr: any) => {
            if (pullErr) {
              reject(pullErr);
            } else {
              resolve(undefined);
            }
          });
        });
      });
    }
  }

  private parseMemoryLimit(limit: string): number {
    const match = limit.match(/^(\d+)([kmg]?)$/i);
    if (!match || !match[1]) return 536870912; // 512MB default
    
    const value = parseInt(match[1]);
    const unit = match[2]?.toLowerCase();
    
    switch (unit) {
      case 'k': return value * 1024;
      case 'm': return value * 1024 * 1024;
      case 'g': return value * 1024 * 1024 * 1024;
      default: return value;
    }
  }

  private parseCpuLimit(limit: string): number {
    const cpuPercent = parseFloat(limit);
    return Math.floor(cpuPercent * 100000); // Docker expects microseconds
  }

  private async collectExecutionOutput(stream: any, timeout: number): Promise<ExecutionResult> {
    return new Promise((resolve, reject) => {
      let stdout = '';
      let stderr = '';
      const startTime = Date.now();
      
      const timeoutId = setTimeout(() => {
        reject(new Error('Execution timeout'));
      }, timeout);

      stream.on('data', (chunk: Buffer) => {
        const data = chunk.toString();
        // Docker multiplexes stdout/stderr in the stream
        // This is a simplified version - real implementation would need proper demultiplexing
        if (data.includes('STDERR:')) {
          stderr += data.replace('STDERR:', '');
        } else {
          stdout += data;
        }
      });

      stream.on('end', () => {
        clearTimeout(timeoutId);
        
        resolve({
          exitCode: 0, // TODO: Get real exit code from exec.inspect()
          stdout: stdout.trim(),
          stderr: stderr.trim(),
          duration: Date.now() - startTime,
          resources: {
            maxMemory: 0, // TODO: Get from container stats
            avgMemory: 0,
            maxCpu: 0,
            avgCpu: 0,
            diskRead: 0,
            diskWrite: 0,
            networkSent: 0,
            networkReceived: 0,
          },
          monitoring: {
            systemCalls: [],
            fileOperations: [],
            networkConnections: [],
            processTree: [],
            environmentChanges: [],
          },
          securityEvents: [],
        });
      });

      stream.on('error', (error: any) => {
        clearTimeout(timeoutId);
        reject(error);
      });
    });
  }

  private generateSandboxId(): string {
    return `sandbox_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

export class SecureSandboxManager implements SandboxManager {
  private sandboxes: Map<string, DockerSandboxEnvironment> = new Map();

  async createSandbox(config: SandboxConfig): Promise<SandboxEnvironment> {
    // Validate configuration
    this.validateSandboxConfig(config);
    
    // Create Docker-based sandbox
    const sandbox = new DockerSandboxEnvironment(config);
    await sandbox.create();
    
    this.sandboxes.set(sandbox.id, sandbox);
    return sandbox as any;
  }

  async destroySandbox(sandboxId: string): Promise<void> {
    const sandbox = this.sandboxes.get(sandboxId);
    if (sandbox) {
      await sandbox.destroy();
      this.sandboxes.delete(sandboxId);
    }
  }

  async execute(sandboxId: string, execution: SandboxExecution): Promise<ExecutionResult> {
    const sandbox = this.sandboxes.get(sandboxId);
    if (!sandbox) {
      throw new Error(`Sandbox ${sandboxId} not found`);
    }

    // Validate execution request
    this.validateExecution(execution);
    
    return await sandbox.execute(execution);
  }

  async monitor(sandboxId: string): Promise<ExecutionMonitoring> {
    const sandbox = this.sandboxes.get(sandboxId);
    if (!sandbox) {
      throw new Error(`Sandbox ${sandboxId} not found`);
    }

    return await sandbox.monitor();
  }

  async listSandboxes(): Promise<SandboxEnvironment[]> {
    return Array.from(this.sandboxes.values()) as any;
  }

  async getSandboxStatus(sandboxId: string): Promise<any> {
    const sandbox = this.sandboxes.get(sandboxId);
    if (!sandbox) {
      throw new Error(`Sandbox ${sandboxId} not found`);
    }

    return await sandbox.getStatus();
  }

  async cleanupSandboxes(): Promise<void> {
    const cleanupPromises = Array.from(this.sandboxes.keys()).map(id => 
      this.destroySandbox(id).catch(error => 
        console.error(`Failed to cleanup sandbox ${id}:`, error)
      )
    );
    
    await Promise.allSettled(cleanupPromises);
  }

  private validateSandboxConfig(config: SandboxConfig): void {
    if (!config.baseDir) {
      throw new Error('Base directory is required');
    }

    if (!config.workingDir) {
      throw new Error('Working directory is required');
    }

    if (config.timeout <= 0) {
      throw new Error('Timeout must be positive');
    }

    // Validate networking configuration
    if (config.networking.enabled && config.networking.allowedHosts) {
      for (const host of config.networking.allowedHosts) {
        if (!this.isValidHost(host)) {
          throw new Error(`Invalid allowed host: ${host}`);
        }
      }
    }
  }

  private validateExecution(execution: SandboxExecution): void {
    if (!execution.command) {
      throw new Error('Command is required');
    }

    // Check for dangerous commands
    const dangerousCommands = ['rm', 'del', 'format', 'dd', 'mkfs', 'fdisk'];
    if (dangerousCommands.some(cmd => execution.command.includes(cmd))) {
      throw new Error(`Dangerous command detected: ${execution.command}`);
    }

    // Validate command arguments
    for (const arg of execution.args) {
      if (this.containsSuspiciousContent(arg)) {
        throw new Error(`Suspicious argument detected: ${arg}`);
      }
    }
  }

  private isValidHost(host: string): boolean {
    // Basic hostname/IP validation
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/;
    
    return ipRegex.test(host) || hostnameRegex.test(host);
  }

  private containsSuspiciousContent(content: string): boolean {
    const suspiciousPatterns = [
      /\.\./,           // Path traversal
      /[;&|`$()]/,      // Command injection
      /rm\s+-rf/,       // Dangerous commands
      /eval|exec/i,     // Code execution
    ];

    return suspiciousPatterns.some(pattern => pattern.test(content));
  }

  /**
   * Create a secure default sandbox configuration
   */
  static createSecureConfig(): SandboxConfig {
    return {
      baseDir: '/tmp/mcp-sandbox',
      workingDir: '/workspace',
      timeout: 30000, // 30 seconds
      cleanup: true,
      persistent: false,
      networking: {
        enabled: false,
        mode: 'none',
        allowedHosts: [],
        blockedHosts: ['localhost', '127.0.0.1', '0.0.0.0'],
        allowedPorts: [],
        blockedPorts: [22, 23, 3389], // SSH, Telnet, RDP
      },
      fileSystem: {
        readOnlyPaths: ['/etc', '/usr', '/lib', '/bin'],
        writablePaths: ['/tmp', '/workspace'],
        mountPoints: [],
        tempDir: '/tmp',
        maxFileSize: '10m',
        allowedExtensions: ['.txt', '.log', '.json'],
        blockedExtensions: ['.exe', '.sh', '.bat', '.ps1'],
      },
      environment: {
        NODE_ENV: 'sandbox',
        PATH: '/usr/local/bin:/usr/bin:/bin',
        USER: 'sandbox',
        HOME: '/workspace',
        MEMORY_LIMIT: '512m',
        CPU_LIMIT: '0.5',
      },
    };
  }

  private generateSandboxId(): string {
    return `sandbox_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

export const sandboxManager = new SecureSandboxManager();

// Sandbox security utilities
export class SandboxSecurityUtils {
  /**
   * Validate file path for sandbox safety
   */
  static validatePath(filePath: string, allowedPaths: string[]): boolean {
    const normalizedPath = path.normalize(filePath);
    
    // Check for path traversal attempts
    if (normalizedPath.includes('..')) {
      return false;
    }

    // Check if path is within allowed directories
    return allowedPaths.some(allowed => 
      normalizedPath.startsWith(path.normalize(allowed))
    );
  }

  /**
   * Sanitize command for execution
   */
  static sanitizeCommand(command: string): string {
    // Remove dangerous characters
    return command.replace(/[;&|`$()]/g, '');
  }

  /**
   * Check if command is safe for execution
   */
  static isSafeCommand(command: string): boolean {
    const dangerousCommands = [
      'rm', 'del', 'format', 'dd', 'mkfs', 'fdisk',
      'sudo', 'su', 'chmod', 'chown',
      'wget', 'curl', 'nc', 'netcat',
      'eval', 'exec', 'system',
    ];

    const lowerCommand = command.toLowerCase();
    return !dangerousCommands.some(dangerous => lowerCommand.includes(dangerous));
  }

  /**
   * Generate security event
   */
  static createSecurityEvent(
    type: string,
    severity: 'low' | 'medium' | 'high' | 'critical',
    description: string,
    details: Record<string, unknown>
  ): SecurityEvent {
    return {
      type: type as any,
      severity,
      description,
      details,
      timestamp: new Date(),
      confidence: 0.8,
      mitigated: false,
    };
  }
}
