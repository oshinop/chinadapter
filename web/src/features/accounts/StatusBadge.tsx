import type { ServiceState } from "@/types";
import { Badge } from "@/components/ui/badge";

interface StatusDetail {
    label: string;
    message: string;
    tone: "ready" | "working" | "warning" | "danger" | "neutral";
}

export const stateDetails: Record<ServiceState, StatusDetail> = {
    signed_out: {
        label: "No providers",
        message: "Add a provider to load nodes.",
        tone: "neutral",
    },
    authenticating: {
        label: "Authenticating",
        message: "Connecting your account.",
        tone: "working",
    },
    syncing: { label: "Syncing", message: "Updating nodes.", tone: "working" },
    ready: { label: "Ready", message: "Service is ready.", tone: "ready" },
    degraded: {
        label: "Needs attention",
        message: "Saved nodes are still available.",
        tone: "warning",
    },
    expired: {
        label: "Expired",
        message: "Add the provider again.",
        tone: "danger",
    },
    error: {
        label: "Service error",
        message: "Service status could not be completed.",
        tone: "danger",
    },
};

export function StatusBadge({ detail }: { detail: StatusDetail }) {
    const tone = {
        ready: {
            badge: "border-led-ok/35 bg-led-ok/10 text-led-ok",
            led: "led--ok",
        },
        working: {
            badge: "border-led-warn/35 bg-led-warn/10 text-led-warn",
            led: "led--warn led--pulse",
        },
        warning: {
            badge: "border-led-warn/35 bg-led-warn/10 text-led-warn",
            led: "led--warn",
        },
        danger: {
            badge: "border-destructive/35 bg-destructive/10 text-destructive",
            led: "led--err",
        },
        neutral: {
            badge: "border-border bg-muted text-muted-foreground",
            led: "",
        },
    }[detail.tone];
    return (
        <Badge className={`h-8 gap-2 px-2.5 ${tone.badge}`} variant="outline">
            <span aria-hidden="true" className={`led ${tone.led}`} />
            {detail.label}
        </Badge>
    );
}
