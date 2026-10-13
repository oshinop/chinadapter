import { useEffect, useMemo, useRef, useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import { ChevronRight, Gauge } from "lucide-react";
import type { ApiClient } from "@/api";
import type { NodeHealth, NodeRecord } from "@/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { isSessionProblem } from "@/lib/errors";
import { compareGroupNames, groupNameCollator } from "@/lib/groups";
import { formatLatency, healthLabel, probeFailureLabel } from "./health";
import { NodeDetailsPopover } from "./NodeDetailsPopover";
import { protocolLabel } from "./protocols";

// Batch scope for the header button; group batches use the group name.
const allNodesScope = "\u0000all";

export function NodeList({
    api,
    getSessionRevision,
    nodes,
    onAccessLost,
    onNodesChange,
}: {
    api: ApiClient;
    getSessionRevision: () => number;
    nodes: NodeRecord[];
    onAccessLost: () => void;
    onNodesChange: Dispatch<SetStateAction<NodeRecord[]>>;
}) {
    const [activeProbe, setActiveProbe] = useState<string | null>(null);
    const [batchScope, setBatchScope] = useState<string | null>(null);
    const probing = batchScope !== null || activeProbe !== null;
    const active = useRef(true);

    useEffect(
        () => () => {
            active.current = false;
        },
        [],
    );

    const markProbeFailed = (nodeId: string, requestError: unknown) => {
        onNodesChange((previous) =>
            previous.map((current) =>
                current.id === nodeId
                    ? {
                          ...current,
                          health: "unhealthy",
                          tcpLatencyMs: undefined,
                          probeError: probeFailureLabel(requestError),
                      }
                    : current,
            ),
        );
    };

    const probe = async (node: NodeRecord) => {
        const revision = getSessionRevision();
        setActiveProbe(node.id);
        try {
            const result = await api.probeNode(node.id);
            if (!active.current || revision !== getSessionRevision()) return;
            onNodesChange((previous) =>
                previous.map((current) =>
                    current.id === node.id
                        ? {
                              ...current,
                              health: result.health,
                              tcpLatencyMs: result.tcpLatencyMs,
                              probeError: undefined,
                          }
                        : current,
                ),
            );
        } catch (requestError) {
            if (!active.current || revision !== getSessionRevision()) return;
            if (isSessionProblem(requestError)) {
                onAccessLost();
                return;
            }
            markProbeFailed(node.id, requestError);
        } finally {
            if (active.current && revision === getSessionRevision())
                setActiveProbe(null);
        }
    };

    const groupedNodes = useMemo(() => {
        const groups = new Map<string, NodeRecord[]>();
        for (const node of nodes) {
            const group = node.group.trim() || "Ungrouped";
            const members = groups.get(group);
            if (members) members.push(node);
            else groups.set(group, [node]);
        }
        return [...groups.entries()]
            .sort(([left], [right]) => compareGroupNames(left, right))
            .map(
                ([group, members]) =>
                    [
                        group,
                        members.sort((left, right) =>
                            groupNameCollator.compare(left.name, right.name),
                        ),
                    ] as const,
            );
    }, [nodes]);

    const probeBatch = async (targets: readonly NodeRecord[], scope: string) => {
        if (targets.length === 0) return;
        const revision = getSessionRevision();
        setBatchScope(scope);
        try {
            for (const node of targets) {
                if (!active.current || revision !== getSessionRevision())
                    return;
                try {
                    const result = await api.probeNode(node.id);
                    if (!active.current || revision !== getSessionRevision())
                        return;
                    onNodesChange((previous) =>
                        previous.map((current) =>
                            current.id === node.id
                                ? {
                                      ...current,
                                      health: result.health,
                                      tcpLatencyMs: result.tcpLatencyMs,
                                      probeError: undefined,
                                  }
                                : current,
                        ),
                    );
                } catch (requestError) {
                    if (!active.current || revision !== getSessionRevision())
                        return;
                    if (isSessionProblem(requestError)) {
                        onAccessLost();
                        return;
                    }
                    markProbeFailed(node.id, requestError);
                }
            }
        } finally {
            if (active.current && revision === getSessionRevision())
                setBatchScope(null);
        }
    };

    return (
        <Card className="panel min-w-0">
            <CardHeader>
                <CardTitle>Nodes</CardTitle>
                <CardDescription>{nodes.length} available</CardDescription>
                <CardAction>
                    <Tooltip>
                        <TooltipTrigger asChild>
                            <Button
                                aria-label="Check TCP reachability for all nodes"
                                disabled={probing || nodes.length === 0}
                                onClick={() =>
                                    void probeBatch(
                                        groupedNodes.flatMap(
                                            ([, members]) => members,
                                        ),
                                        allNodesScope,
                                    )
                                }
                                size="icon"
                                variant="ghost"
                            >
                                <Gauge
                                    className={
                                        batchScope === allNodesScope
                                            ? "size-4 animate-pulse"
                                            : "size-4"
                                    }
                                />
                            </Button>
                        </TooltipTrigger>
                        <TooltipContent>Check TCP reachability</TooltipContent>
                    </Tooltip>
                </CardAction>
            </CardHeader>
            <CardContent className="min-w-0">
                <div
                    aria-label="Nodes by group"
                    className="grid gap-2.5"
                    role="tree"
                >
                    {groupedNodes.map(([group, members], groupIndex) => (
                        <details
                            aria-label={`${group} group`}
                            className="node-group overflow-hidden rounded-sm border border-border bg-background/40"
                            key={group}
                            role="treeitem"
                        >
                            <summary className="flex cursor-pointer list-none items-center gap-2.5 px-3 py-2.5 text-sm font-medium transition-colors hover:bg-primary/5 [&::-webkit-details-marker]:hidden">
                                <ChevronRight
                                    aria-hidden="true"
                                    className="node-group__chevron size-4 text-muted-foreground"
                                />
                                <span
                                    aria-hidden="true"
                                    className="font-sans text-xs font-semibold tabular-nums text-primary/80"
                                >
                                    {String(groupIndex + 1).padStart(2, "0")}
                                </span>
                                <span className="min-w-0 flex-1 truncate">
                                    {group}
                                </span>
                                <Badge variant="secondary">
                                    {members.length}
                                </Badge>
                                <Tooltip>
                                    <TooltipTrigger asChild>
                                        <Button
                                            aria-label={`Check TCP reachability for the ${group} group`}
                                            className="size-7"
                                            disabled={probing}
                                            onClick={(event) => {
                                                // Keep the summary from toggling the group.
                                                event.preventDefault();
                                                event.stopPropagation();
                                                void probeBatch(members, group);
                                            }}
                                            size="icon"
                                            variant="ghost"
                                        >
                                            <Gauge
                                                className={
                                                    batchScope === group
                                                        ? "size-4 animate-pulse"
                                                        : "size-4"
                                                }
                                            />
                                        </Button>
                                    </TooltipTrigger>
                                    <TooltipContent>
                                        Check this group
                                    </TooltipContent>
                                </Tooltip>
                            </summary>
                            <div className="node-group__content" role="group">
                                <div className="node-group__content-inner divide-y divide-border border-t border-border">
                                    {members.map((node) => (
                                        <article
                                            aria-label={node.name}
                                            className="grid gap-3 p-3 transition-colors hover:bg-primary/[0.04] sm:grid-cols-[minmax(0,1fr)_auto_auto] sm:items-center"
                                            key={node.id}
                                            role="treeitem"
                                        >
                                            <div className="min-w-0">
                                                <div className="flex min-w-0 items-center gap-2">
                                                    <p className="truncate text-sm font-medium">
                                                        {node.name}
                                                    </p>
                                                    <Badge
                                                        className="shrink-0 px-1.5 py-0 text-[0.65rem] font-medium tracking-wide"
                                                        title={`Upstream protocol: ${node.protocol}`}
                                                        variant="outline"
                                                    >
                                                        {protocolLabel(
                                                            node.protocol,
                                                        )}
                                                    </Badge>
                                                </div>
                                                <p className="mt-0.5 text-[0.65rem] uppercase tracking-[0.18em] text-muted-foreground">
                                                    {node.provider}
                                                </p>
                                            </div>
                                            <LatencyReadout node={node} />
                                            <div className="flex justify-end gap-1">
                                                <NodeDetailsPopover
                                                    api={api}
                                                    getSessionRevision={
                                                        getSessionRevision
                                                    }
                                                    node={node}
                                                    onAccessLost={onAccessLost}
                                                />
                                                <Tooltip>
                                                    <TooltipTrigger asChild>
                                                        <Button
                                                            aria-label={`Check TCP reachability for ${node.name}`}
                                                            disabled={probing}
                                                            onClick={() =>
                                                                void probe(node)
                                                            }
                                                            size="icon"
                                                            variant="ghost"
                                                        >
                                                            <Gauge
                                                                className={
                                                                    activeProbe ===
                                                                    node.id
                                                                        ? "size-4 animate-pulse"
                                                                        : "size-4"
                                                                }
                                                            />
                                                        </Button>
                                                    </TooltipTrigger>
                                                    <TooltipContent>
                                                        Check TCP reachability
                                                    </TooltipContent>
                                                </Tooltip>
                                            </div>
                                        </article>
                                    ))}
                                </div>
                            </div>
                        </details>
                    ))}
                </div>
                {groupedNodes.length === 0 ? (
                    <p className="px-1 py-8 text-sm text-muted-foreground">
                        No nodes available.
                    </p>
                ) : null}
            </CardContent>
        </Card>
    );
}

function LatencyReadout({ node }: { node: NodeRecord }) {
    const text = node.probeError || formatLatency(node.tcpLatencyMs);
    const tone: Record<NodeHealth, string> = {
        healthy: "text-led-ok",
        degraded: "text-led-warn",
        unhealthy: "text-led-err",
        unknown: "text-muted-foreground",
    };
    return (
        <span
            aria-label={`TCP reachability ${text}, ${healthLabel(node.health)}`}
            className={`text-xs font-medium tabular-nums sm:text-right ${tone[node.health]}`}
        >
            {text}
        </span>
    );
}
