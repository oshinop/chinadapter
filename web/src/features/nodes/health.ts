import { ApiError } from "@/api";
import type { NodeHealth } from "@/types";

export function formatLatency(value?: number): string {
    return typeof value === "number" ? `${value} ms` : "—";
}

export function probeFailureLabel(error: unknown): string {
    if (!(error instanceof ApiError)) return "Failed";
    switch (error.problem.code) {
        case "node_ineligible":
            return "Ineligible";
        case "node_not_found":
        case "node_snapshot_unavailable":
            return "Unavailable";
        case "probe_busy":
            return "Busy";
        case "stale_probe":
            return "Changed";
        case "tcp_probe_timeout":
            return "Timeout";
        case "tcp_probe_failed":
        case "probe_failed":
            return "Unreachable";
        default:
            return "Failed";
    }
}

export function healthLabel(health: NodeHealth): string {
    return health.slice(0, 1).toUpperCase() + health.slice(1);
}
