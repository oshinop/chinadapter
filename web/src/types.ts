export type ServiceState =
  | "signed_out"
  | "authenticating"
  | "syncing"
  | "ready"
  | "degraded"
  | "expired"
  | "error";

export type NodeHealth = "healthy" | "degraded" | "unhealthy" | "unknown";

export interface AccountSummary {
  provider: string;
  display: string;
  tier: string;
  subscriptionActive: boolean;
  subscriptionEndsAt?: string;
}

export interface StatusResponse {
  state: ServiceState;
  version: string;
  deployment: {
    mode: "container" | string;
    startedAt?: string;
  };
  providers: string[];
  accounts?: Record<string, AccountSummary>;
  controlPlane: {
    lastRefreshAt?: string;
    nextRefreshAt?: string;
  };
  dataPlane: {
    socksAddress: string;
    udpMode: "provider_transport";
  };
  nodes: {
    total: number;
    eligible: number;
    healthy: number;
  };
  subscription: {
    active: boolean;
    nodeCount: number;
  };
}

export interface NodeRecord {
  id: string;
  name: string;
  group: string;
  provider: string;
  protocol: string;
  health: NodeHealth;
  tcpLatencyMs?: number;
  probeError?: string;
  udpHealth: "unavailable" | "healthy" | "unhealthy" | string;
  eligible: boolean;
  compatibilityError?: string;
}

export interface NodeDetails {
  id: string;
  name: string;
  group: string;
  provider: string;
  upstreamHost: string;
  upstreamPort: number;
  socksAddress: string;
  socksUsername: string;
  /** Installation-wide lowercase UUIDv8; shared by every node. */
  socksPassword: string;
  health: NodeHealth;
  tcpLatencyMs?: number;
}

export interface NodesResponse {
  nodes: NodeRecord[];
}

export interface SubscriptionMetadata {
  active: boolean;
  nodeCount: number;
}

export interface SubscriptionURLResponse {
  /** Absolute URL ending in /sub/<lowercase canonical UUIDv8>. */
  url: string;
}


export interface AccessStatusResponse {
  initialized: boolean;
  authenticated: boolean;
  expiresAt?: string;
}

export interface AccessSessionResponse {
  expiresAt?: string;
}

export interface AccessTokenChangeInput {
  current: string;
  next: string;
}

export interface LoginResponse {
  account?: AccountSummary;
  status?: StatusResponse;
}

export interface ProbeResult {
  nodeId: string;
  health: NodeHealth;
  tcpLatencyMs?: number;
  probedAt: string;
}

export type EventMessage =
  | { type: "state"; state: ServiceState }
  | { type: "refresh"; state: ServiceState; complete: boolean }
  | { type: "probe"; nodeId: string; health: NodeHealth; tcpLatencyMs?: number; probedAt: string };
