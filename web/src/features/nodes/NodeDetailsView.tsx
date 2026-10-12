import { useEffect, useRef, useState } from "react";
import { Copy } from "lucide-react";
import type { NodeDetails } from "@/types";
import { Button } from "@/components/ui/button";
import { copyText } from "@/lib/clipboard";
import { formatLatency, healthLabel } from "./health";

export function NodeDetailsView({ details }: { details: NodeDetails }) {
    const [copyMessage, setCopyMessage] = useState("");
    const copyResetTimer = useRef<number | undefined>(undefined);
    const socksURL = `socks5://${encodeURIComponent(details.socksUsername)}:${encodeURIComponent(details.socksPassword)}@${details.socksAddress}`;

    const clearCopyMessage = () => {
        clearTimeout(copyResetTimer.current);
        copyResetTimer.current = undefined;
        setCopyMessage("");
    };

    useEffect(() => () => clearTimeout(copyResetTimer.current), []);

    const copySocksURL = async () => {
        clearCopyMessage();
        setCopyMessage(
            (await copyText(socksURL))
                ? "SOCKS5 URL copied."
                : "Copy is unavailable.",
        );
        copyResetTimer.current = window.setTimeout(
            () => setCopyMessage(""),
            2500,
        );
    };

    return (
        <div className="grid gap-4">
            <dl className="grid gap-2.5 text-sm">
                <DetailRow
                    label="Upstream"
                    value={`${details.upstreamHost}:${details.upstreamPort}`}
                />
                <div className="grid grid-cols-3 gap-3 border-t border-dashed border-border pt-3">
                    <DetailRow
                        label="Health"
                        value={healthLabel(details.health)}
                    />
                    <DetailRow
                        label="Latency"
                        value={formatLatency(details.tcpLatencyMs)}
                    />
                </div>
            </dl>
            <div className="flex flex-wrap items-center gap-3">
                <Button
                    onClick={() => void copySocksURL()}
                    size="sm"
                    variant="outline"
                >
                    <Copy className="size-4" />
                    Copy SOCKS5 URL
                </Button>
                <p
                    aria-live="polite"
                    className="min-h-5 text-xs text-muted-foreground"
                    role="status"
                >
                    {copyMessage}
                </p>
            </div>
        </div>
    );
}

function DetailRow({ label, value }: { label: string; value: string }) {
    return (
        <div className="min-w-0">
            <dt className="text-[0.625rem] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
                {label}
            </dt>
            <dd className="mt-1 break-all font-mono text-xs text-primary/90">
                {value}
            </dd>
        </div>
    );
}
