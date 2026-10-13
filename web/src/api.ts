import type {
  AccessSessionResponse,
  AccessStatusResponse,
  AccessTokenChangeInput,
  EventMessage,
  LoginResponse,
  NodeDetails,
  NodeHealth,
  NodeRecord,
  NodesResponse,
  ProbeResult,
  ServiceState,
  StatusResponse,
  SubscriptionURLResponse,
} from "./types";

export interface ProblemDetails {
  type?: string;
  title: string;
  status: number;
  code: string;
  detail?: string;
}

export class ApiError extends Error {
  readonly problem: ProblemDetails;

  constructor(problem: ProblemDetails) {
    super(problem.detail || problem.title);
    this.name = "ApiError";
    this.problem = problem;
  }
}

const API_ROOT = "/api/v1";


async function asProblem(response: Response): Promise<ApiError> {
  let problem: Partial<ProblemDetails> = {};
  try {
    problem = (await response.json()) as Partial<ProblemDetails>;
  } catch {
    // The server may reject before it can issue a problem document.
  }
  return new ApiError({
    title: problem.title || "Request rejected",
    status: response.status,
    code: problem.code || `http_${response.status}`,
    detail: problem.detail,
    type: problem.type,
  });
}

const serviceStates: readonly ServiceState[] = ["signed_out", "authenticating", "syncing", "ready", "degraded", "expired", "error"];
const nodeHealths: readonly NodeHealth[] = ["healthy", "degraded", "unhealthy", "unknown"];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonnegativeSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function parseNamedEvent(type: "state" | "refresh" | "probe", data: string): EventMessage | null {
  let payload: unknown;
  try {
    payload = JSON.parse(data);
  } catch {
    return null;
  }
  if (!isRecord(payload)) return null;

  if (type === "state") {
    if (typeof payload.state !== "string" || !serviceStates.includes(payload.state as ServiceState)) return null;
    return { type, state: payload.state as ServiceState };
  }
  if (type === "refresh") {
    if (typeof payload.state !== "string" || !serviceStates.includes(payload.state as ServiceState) || typeof payload.complete !== "boolean") return null;
    return { type, state: payload.state as ServiceState, complete: payload.complete };
  }
  if (type === "probe") {
    if (
      typeof payload.nodeId !== "string" || payload.nodeId.length === 0 ||
      typeof payload.health !== "string" || !nodeHealths.includes(payload.health as NodeHealth) ||
      typeof payload.probedAt !== "string" || payload.probedAt.length === 0 ||
      (payload.tcpLatencyMs !== undefined && !isNonnegativeSafeInteger(payload.tcpLatencyMs))
    ) return null;
    return payload.tcpLatencyMs === undefined
      ? { type, nodeId: payload.nodeId, health: payload.health as NodeHealth, probedAt: payload.probedAt }
      : { type, nodeId: payload.nodeId, health: payload.health as NodeHealth, tcpLatencyMs: payload.tcpLatencyMs, probedAt: payload.probedAt };
  }
  return null;
}

export class ApiClient {
  async accessStatus(): Promise<AccessStatusResponse> {
    return this.request<AccessStatusResponse>("/access/status");
  }

  async setupAccess(token: string): Promise<AccessSessionResponse> {
    return this.request<AccessSessionResponse>("/access/setup", { method: "POST", body: { token } });
  }

  async loginAccess(token: string): Promise<AccessSessionResponse> {
    return this.request<AccessSessionResponse>("/access/login", { method: "POST", body: { token } });
  }

  async changeAccessToken(current: string, next: string): Promise<AccessSessionResponse> {
    const body: AccessTokenChangeInput = { current, next };
    return this.request<AccessSessionResponse>("/access/token", { method: "POST", body });
  }
  async status(): Promise<StatusResponse> {
    return this.request<StatusResponse>("/status");
  }

  async nodes(): Promise<NodesResponse> {
    const response = await this.request<NodesResponse>("/nodes");
    return {
      nodes: response.nodes.map((node) => ({
        id: node.id,
        name: node.name,
        group: node.group,
        provider: node.provider,
        protocol: node.protocol,
        health: node.health,
        tcpLatencyMs: node.tcpLatencyMs,
        udpHealth: node.udpHealth,
        eligible: node.eligible,
        compatibilityError: node.compatibilityError,
      })),
    };
  }

  async nodeDetails(id: string): Promise<NodeDetails> {
    return this.request<NodeDetails>(`/nodes/${encodeURIComponent(id)}/details`);
  }



  async login(provider: string, account: string, password: string): Promise<LoginResponse> {
    return this.request<LoginResponse>("/auth/login", {
      method: "POST",
      body: { provider, account, password },
    });
  }

  async logoutAccount(provider: string): Promise<void> {
    await this.request<void>("/auth/logout", { method: "POST", body: { provider }, expectEmptyResponse: true });
  }

  async lockConsole(): Promise<void> {
    try {
      await this.request<void>("/access/logout", { method: "POST", body: {}, expectEmptyResponse: true });
    } catch (error) {
      if (error instanceof ApiError && error.problem.status === 401) return;
      throw error;
    }
  }

  async refresh(provider: string): Promise<void> {
    await this.request<void>("/control/refresh", { method: "POST", body: { provider }, expectEmptyResponse: true });
  }

  async probeNode(id: string): Promise<ProbeResult> {
    return this.request<ProbeResult>(`/nodes/${encodeURIComponent(id)}/probe`, {
      method: "POST",
      body: {},
    });
  }


  async subscriptionURL(): Promise<SubscriptionURLResponse> {
    return this.request<SubscriptionURLResponse>("/subscription/url");
  }


  events(onEvent: (event: EventMessage) => void, onFailure: () => void): () => void {
    const stream = new EventSource(`${API_ROOT}/events`, { withCredentials: true });
    const names = ["state", "refresh", "probe"] as const;
    const listeners = names.map((type) => {
      const listener = (message: Event) => {
        const data = (message as MessageEvent<unknown>).data;
        if (typeof data !== "string") return;
        const event = parseNamedEvent(type, data);
        if (event) onEvent(event);
      };
      stream.addEventListener(type, listener);
      return [type, listener] as const;
    });
    stream.onerror = () => onFailure();
    return () => {
      for (const [type, listener] of listeners) stream.removeEventListener(type, listener);
      stream.close();
    };
  }

  private async request<T>(
    path: string,
    init: { method?: "POST" | "PUT" | "DELETE"; body?: unknown; expectEmptyResponse?: boolean } = {},
  ): Promise<T> {
    const isWrite = Boolean(init.method);
    const response = await fetch(`${API_ROOT}${path}`, {
      method: init.method || "GET",
      credentials: "same-origin",
      cache: "no-store",
      headers: {
        Accept: "application/json",
        ...(isWrite
          ? {
              "Content-Type": "application/json",
            }
          : {}),
      },
      ...(isWrite ? { body: JSON.stringify(init.body ?? {}) } : {}),
    });
    if (!response.ok) throw await asProblem(response);
    if (init.expectEmptyResponse || response.status === 204) return undefined as T;
    return (await response.json()) as T;
  }
}
