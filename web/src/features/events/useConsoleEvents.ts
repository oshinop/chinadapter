import { useEffect, useRef } from "react";
import type { Dispatch, SetStateAction } from "react";
import type { ApiClient } from "@/api";
import type { EventMessage, NodeRecord } from "@/types";
import type { SessionState } from "@/features/access/session";

export function useConsoleEvents({
    api,
    queueAuthenticatedReload,
    session,
    setNodes,
}: {
    api: ApiClient;
    queueAuthenticatedReload: () => void;
    session: SessionState;
    setNodes: Dispatch<SetStateAction<NodeRecord[]>>;
}) {
    const nextSSEFailureReloadAt = useRef(0);

    useEffect(() => {
        if (session !== "available") return;
        let active = true;
        const closeEvents = api.events(
            (event: EventMessage) => {
                if (!active) return;
                if (event.type === "probe") {
                    setNodes((previous) =>
                        previous.map((node) =>
                            node.id === event.nodeId
                                ? {
                                      ...node,
                                      health: event.health,
                                      tcpLatencyMs: event.tcpLatencyMs,
                                      probeError: undefined,
                                  }
                                : node,
                        ),
                    );
                    return;
                }
                queueAuthenticatedReload();
            },
            () => {
                if (!active) return;
                const now = Date.now();
                if (now < nextSSEFailureReloadAt.current) return;
                nextSSEFailureReloadAt.current = now + 1000;
                queueAuthenticatedReload();
            },
        );
        return () => {
            active = false;
            closeEvents();
        };
    }, [api, queueAuthenticatedReload, session]);
}
