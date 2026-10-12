import { useEffect, useRef, useState } from "react";
import { Info, LoaderCircle } from "lucide-react";
import type { ApiClient } from "@/api";
import type { NodeDetails, NodeRecord } from "@/types";
import { FormError } from "@/components/forms";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { describeError, isSessionProblem } from "@/lib/errors";
import { NodeDetailsView } from "./NodeDetailsView";

export function NodeDetailsPopover({
    api,
    getSessionRevision,
    node,
    onAccessLost,
}: {
    api: ApiClient;
    getSessionRevision: () => number;
    node: NodeRecord;
    onAccessLost: () => void;
}) {
    const [open, setOpen] = useState(false);
    const [details, setDetails] = useState<NodeDetails | null>(null);
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);
    const requestId = useRef(0);

    useEffect(
        () => () => {
            requestId.current += 1;
        },
        [],
    );

    const onOpenChange = (nextOpen: boolean) => {
        requestId.current += 1;
        const currentRequest = requestId.current;
        setOpen(nextOpen);
        setDetails(null);
        setError("");
        setLoading(nextOpen);
        if (!nextOpen) return;

        const revision = getSessionRevision();
        api.nodeDetails(node.id)
            .then((response) => {
                if (
                    currentRequest !== requestId.current ||
                    revision !== getSessionRevision()
                )
                    return;
                setDetails(response);
            })
            .catch((requestError: unknown) => {
                if (
                    currentRequest !== requestId.current ||
                    revision !== getSessionRevision()
                )
                    return;
                if (isSessionProblem(requestError)) {
                    onAccessLost();
                    return;
                }
                setError(describeError(requestError));
            })
            .finally(() => {
                if (
                    currentRequest === requestId.current &&
                    revision === getSessionRevision()
                )
                    setLoading(false);
            });
    };

    return (
        <Popover onOpenChange={onOpenChange} open={open}>
            <Tooltip>
                <TooltipTrigger asChild>
                    <PopoverTrigger asChild>
                        <Button
                            aria-label={`Details for ${node.name}`}
                            size="icon"
                            variant="ghost"
                        >
                            <Info className="size-4" />
                        </Button>
                    </PopoverTrigger>
                </TooltipTrigger>
                <TooltipContent>Details</TooltipContent>
            </Tooltip>
            <PopoverContent
                align="end"
                className="panel w-[min(25rem,calc(100vw-2rem))] p-0"
            >
                <div className="flex flex-col gap-4 py-4">
                    <div className="grid gap-1 px-4">
                        <h2 className="font-sans text-sm font-semibold uppercase tracking-[0.1em]">
                            {node.name}
                        </h2>
                        <p className="text-xs text-muted-foreground">
                            {node.group} · {node.provider}
                        </p>
                    </div>
                    <div className="px-4">
                        {loading ? (
                            <p className="flex items-center gap-2 text-sm text-muted-foreground">
                                <LoaderCircle className="size-4 animate-spin" />
                                Loading details
                            </p>
                        ) : null}
                        {error ? <FormError message={error} /> : null}
                        {details ? <NodeDetailsView details={details} /> : null}
                    </div>
                </div>
            </PopoverContent>
        </Popover>
    );
}
