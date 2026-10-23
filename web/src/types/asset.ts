// Registered assets, ports and business groups.
export type PortKind = 'WEB' | 'NON_WEB' | 'EXCLUDED_PROXY';

export interface AssetPort {
  port: number;
  kind: PortKind;
  source: string;
}

export interface PortQuarantine {
  assetId: string;
  address: string;
  port: number;
  reason: string;
  detectedAt: string;
  status: 'ACTIVE' | 'RELEASED';
  reviewedBy?: string;
  reviewedAt?: string;
}

export interface LoginEntry { type: 'system'|'web'; name: string; port: number; url?: string; https: boolean; captcha?: boolean|null; antiBruteForce?: boolean|null; evidence?: string }
export interface AssetService { port: number; scheme?: string; kind?: 'HTTP'|'OTHER'; protocol?: string; state?: string; serviceName?: string; software?: string; version?: string; middleware?: string; language?: string; framework?: string; database?: string; application?: string; url?: string; title?: string; tls?: boolean; firstSeen?: string; lastSeen?: string; excluded?: boolean; quarantined?: boolean; quarantineReason?: string; loginEntries?: LoginEntry[] }
export interface RuntimeService { name: string; manager: 'systemd'|'init'|'process'|'container'; state: 'installed'|'running'|'stopped'; runtime?: 'docker'|'podman'; image?: string }
export interface AssetProfile { name?: string; isCore?: boolean; department?: string; phone?: string; mac?: string; osName?: string; osFamily?: string; deviceType?: string; deviceSubtype?: string; vendor?: string; model?: string; runtimeServices?: RuntimeService[] }
export interface Asset extends AssetProfile {
  id: string;
  kind: 'host' | 'image_repo';
  address: string;
  resolvedIp?: string;
  businessGroup: string;
  owner: string;
  createdAt: string;
  ports: AssetPort[];
  services?: AssetService[];
  loginEntries?: LoginEntry[];
  requestedPorts?: number[]; // Registration request only; NOT an approved scan port
  quarantinedPorts?: number[];
  skippedPorts?: number[];
  reachabilityStatus?: 'UNCHECKED'|'REACHABLE'|'NO_RESPONSE'|'CHECK_FAILED';
  reachabilityCheckedAt?: string;
}

export interface BusinessGroup {
  name: string;
  assetCount: number;
  createdAt: string;
}

export interface AssetImportHistory {
  id: string;
  actor: string;
  imported: number;
  total: number;
  createdAt: string;
}
