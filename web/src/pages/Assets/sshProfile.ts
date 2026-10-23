// Builds the Worker-local SSH collection config (ssh-config.json) in the
// browser. It never leaves the browser: the Server must not receive SSH
// settings, and no private key or password is entered here, only the path of
// a key file that already sits on the Worker. The checks mirror
// internal/sshcollect Load and validateApplications so the Worker accepts the
// file as generated.

export type SshAuth = 'agent' | 'private-key';

export interface SshApp {
  alias: string;
  directory: string;
  includeJava: boolean;
  includeGo: boolean;
}

export interface SshTargetDraft {
  ip: string;
  sshPort: number;
  user: string;
  auth: SshAuth;
  privateKeyFile?: string;
  apps?: SshApp[];
}

export interface SshConfigDraft {
  knownHostsFile: string;
  targets: SshTargetDraft[];
}

const userPattern = /^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/;
const aliasPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const maxTargets = 1000;
const maxApps = 8;
const pseudoRoots = ['/proc', '/sys', '/dev', '/run', '/tmp', '/net', '/mnt', '/media'];
const broadParents = ['/opt', '/srv', '/home', '/root', '/etc', '/usr', '/usr/local', '/var', '/var/lib', '/var/www', '/var/opt', '/var/local', '/bin', '/sbin', '/lib', '/lib64', '/boot'];

/** Canonical numeric IPv4, or an IPv6 address already in lowercase compressed form. */
export function canonicalIP(value: string): boolean {
  const v4 = value.split('.');
  if (v4.length === 4) {
    return v4.every(part => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255) && value !== '0.0.0.0' && !(Number(v4[0]) >= 224 && Number(v4[0]) <= 239);
  }
  if (!value.includes(':') || value.includes('%') || value !== value.toLowerCase() || value === '::') return false;
  if (value.startsWith('ff')) return false;
  if ((value.match(/::/g) ?? []).length > 1) return false;
  const groups = value.split(':').filter((part, index, all) => part !== '' || index === 0 || index === all.length - 1);
  return groups.every(part => part === '' || /^(0|[1-9a-f][0-9a-f]{0,3})$/.test(part)) && groups.length <= 8;
}

/** A Worker-local file path: absolute, or relative to the config file without leaving its directory. */
export function validLocalPath(value: string): boolean {
  if (!value || value.includes('\0') || value.length > 1024) return false;
  if (value.startsWith('/') || /^[A-Za-z]:[\\/]/.test(value) || value.startsWith('\\\\')) return true;
  return value.split(/[\\/]/).every(part => part !== '..' && part !== '') && !/^[A-Za-z]:/.test(value);
}

/** Same rules as validApplicationDirectory on the Worker. */
export function validAppDirectory(value: string): boolean {
  if (new TextEncoder().encode(value).length > 512 || !value.startsWith('/') || value === '/') return false;
  if (/[\u0000-\u001f\u007f-\u009f]/.test(value)) return false;
  const parts = value.split('/').slice(1);
  if (parts.some(part => part === '' || part === '.' || part === '..')) return false;
  if (pseudoRoots.some(root => value === root || value.startsWith(root + '/'))) return false;
  return !broadParents.includes(value);
}

/** Problems in the draft, in Chinese, keyed by where they are. Empty means the Worker will load it. */
export function validateSshConfig(config: SshConfigDraft): string[] {
  const errors: string[] = [];
  if (!validLocalPath(config.knownHostsFile)) errors.push('known_hosts 路径必须是 Worker 上的绝对路径，或相对于配置文件且不含 ..');
  if (config.targets.length === 0) errors.push('至少选择一台主机');
  if (config.targets.length > maxTargets) errors.push(`一个配置文件最多 ${maxTargets} 台主机`);
  const seen = new Set<string>();
  for (const target of config.targets) {
    const where = target.ip || '未填写地址';
    if (!canonicalIP(target.ip)) errors.push(`${where}：只支持规范的数字 IP（不支持主机名、网段或多播地址）`);
    if (seen.has(target.ip)) errors.push(`${where}：同一 IP 只能配置一次`);
    seen.add(target.ip);
    if (!Number.isInteger(target.sshPort) || target.sshPort < 1 || target.sshPort > 65535) errors.push(`${where}：SSH 端口须为 1–65535`);
    if (!userPattern.test(target.user)) errors.push(`${where}：账号须以字母或下划线开头，最多 32 个字母、数字、. _ -`);
    if (target.auth === 'private-key') {
      if (!target.privateKeyFile || !validLocalPath(target.privateKeyFile)) errors.push(`${where}：私钥文件须是 Worker 上的路径（绝对路径，或相对配置文件且不含 ..）`);
    } else if (target.auth !== 'agent') {
      errors.push(`${where}：认证方式只能是 SSH Agent 或私钥文件`);
    }
    const apps = target.apps ?? [];
    if (apps.length > maxApps) errors.push(`${where}：每台主机最多 ${maxApps} 个应用目录`);
    const aliases = new Set<string>();
    for (const app of apps) {
      const label = `${where} 应用 ${app.alias || '未命名'}`;
      if (!aliasPattern.test(app.alias)) errors.push(`${label}：别名须以字母或数字开头，最多 64 个字母、数字、_ -`);
      if (aliases.has(app.alias)) errors.push(`${label}：别名重复`);
      aliases.add(app.alias);
      if (!app.includeJava && !app.includeGo) errors.push(`${label}：至少选择 Java 或 Go`);
      if (!validAppDirectory(app.directory)) errors.push(`${label}：目录须是具体的绝对部署路径，不能是 /opt、/srv 等宽泛目录或 /tmp、/proc 等系统目录`);
    }
  }
  return errors;
}

/** JSON exactly in the Worker's schema: unknown fields are rejected there, so only known ones are written. */
export function buildSshConfig(config: SshConfigDraft): string {
  const targets = config.targets.map(target => ({
    ip: target.ip,
    sshPort: target.sshPort,
    user: target.user,
    auth: target.auth,
    ...(target.auth === 'private-key' ? { privateKeyFile: target.privateKeyFile } : {}),
    ...(target.apps?.length ? { apps: target.apps.map(app => ({ alias: app.alias, directory: app.directory, includeJava: app.includeJava, includeGo: app.includeGo })) } : {}),
  }));
  return JSON.stringify({ knownHostsFile: config.knownHostsFile, targets }, null, 2) + '\n';
}

/** Commands the operator runs on the Worker to collect host keys for checking; they are not proof of trust. */
export function keyscanCommands(targets: Pick<SshTargetDraft, 'ip' | 'sshPort'>[]): string {
  return targets.map(target => `ssh-keyscan -p ${target.sshPort} ${target.ip}`).join('\n');
}
