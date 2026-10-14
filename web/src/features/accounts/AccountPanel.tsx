import { LogOut, RefreshCw } from "lucide-react";
import type { AccountSummary, NodeRecord, StatusResponse } from "@/types";
import { FormError } from "@/components/forms";
import { Metric } from "@/components/Metric";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { formatCompactTime, formatTime } from "@/lib/time";
import { accountIssue, accountTone, lampClass } from "./accountHealth";
import type { AccountIssue } from "./accountHealth";
import { ProviderCredentialsForm } from "./ProviderCredentialsForm";
import { SubscriptionMetric } from "./SubscriptionMetric";
import { providerLabel } from "./providers";
import type { AccountViews } from "./useAccountViews";

const removeAllKey = "\u0000all";
const footerClassName =
    "flex-wrap justify-between gap-3 border-t border-dashed border-border/70 pt-4 [&.border-t]:pt-4";

export function AccountPanel({
    accountView,
    eligibleNodes,
    onLoginAccount,
    onRefreshAll,
    onRefreshProvider,
    onRemoveProvider,
    onSignOutAll,
    refreshing,
    status,
}: {
    accountView: AccountViews;
    eligibleNodes: NodeRecord[];
    onLoginAccount: (provider: string, fields: Record<string, string>) => Promise<void>;
    onRefreshAll: () => Promise<void>;
    onRefreshProvider: (provider: string) => Promise<void>;
    onRemoveProvider: (provider: string) => Promise<void>;
    onSignOutAll: () => Promise<void>;
    refreshing: boolean;
    status: StatusResponse;
}) {
    const {
        activeProvider,
        confirmRemoval,
        providerBusy,
        providerError,
        runProviderAction,
        selectProvider,
        setConfirmRemoval,
    } = accountView;
    const accounts = status.accounts ?? {};
    const linkedCount = Object.keys(accounts).length;
    // A public provider (no credential fields) has no account identity to show.
    const isPublic = (provider: string) =>
        status.providerAuth?.[provider]?.fields.length === 0;

    if (activeProvider === "all") {
        return (
            <Card className="panel">
                <CardHeader>
                    <CardTitle>Providers</CardTitle>
                </CardHeader>
                <CardContent className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                    {status.providers.map((provider) => (
                        <ProviderTile
                            account={accounts[provider]}
                            isPublic={isPublic(provider)}
                            key={provider}
                            nodeCount={
                                eligibleNodes.filter(
                                    (node) => node.provider === provider,
                                ).length
                            }
                            onSelect={() => selectProvider(provider)}
                            provider={provider}
                        />
                    ))}
                </CardContent>
                <CardFooter className={footerClassName}>
                    <p
                        className="flex min-w-0 items-center gap-2 text-xs text-muted-foreground"
                        title={`Updated ${formatTime(status.controlPlane.lastRefreshAt)}`}
                    >
                        <span
                            aria-hidden="true"
                            className={`led ${refreshing ? "led--warn led--pulse" : "led--ok"}`}
                        />
                        <span className="truncate">
                            {status.nodes.eligible} of {status.nodes.total} nodes
                            usable · Updated{" "}
                            {formatCompactTime(status.controlPlane.lastRefreshAt)}
                        </span>
                    </p>
                    <div className="flex w-full flex-wrap gap-2 sm:ml-auto sm:w-auto sm:justify-end">
                        {confirmRemoval === removeAllKey ? (
                            <>
                                <Button
                                    onClick={() => setConfirmRemoval("")}
                                    size="sm"
                                    variant="ghost"
                                >
                                    Cancel
                                </Button>
                                <Button
                                    disabled={refreshing || providerBusy}
                                    onClick={() =>
                                        void runProviderAction(onSignOutAll)
                                    }
                                    size="sm"
                                    variant="destructive"
                                >
                                    <LogOut />
                                    Remove {linkedCount}{" "}
                                    {linkedCount === 1 ? "provider" : "providers"}
                                </Button>
                            </>
                        ) : (
                            <>
                                <Button
                                    disabled={refreshing || providerBusy}
                                    onClick={() => void onRefreshAll()}
                                    size="sm"
                                    variant="outline"
                                >
                                    <RefreshCw
                                        className={
                                            refreshing
                                                ? "size-4 animate-spin"
                                                : "size-4"
                                        }
                                    />
                                    Refresh all
                                </Button>
                                <Button
                                    className="border-destructive/60 text-destructive hover:border-destructive hover:bg-destructive/10 hover:text-destructive"
                                    disabled={
                                        refreshing ||
                                        providerBusy ||
                                        linkedCount === 0
                                    }
                                    onClick={() =>
                                        setConfirmRemoval(removeAllKey)
                                    }
                                    size="sm"
                                    variant="outline"
                                >
                                    <LogOut />
                                    Remove all
                                </Button>
                            </>
                        )}
                    </div>
                </CardFooter>
                {providerError ? (
                    <div className="px-6 pb-2">
                        <FormError message={providerError} />
                    </div>
                ) : null}
            </Card>
        );
    }

    const activeAccount = accounts[activeProvider];
    if (!activeAccount) {
        return (
            <Card className="panel max-w-xl">
                <CardHeader>
                    <CardTitle>Add {providerLabel(activeProvider)}</CardTitle>
                </CardHeader>
                <CardContent>
                    <ProviderCredentialsForm
                        fixedProvider={activeProvider}
                        idPrefix={`add-${activeProvider}`}
                        key={activeProvider}
                        onSubmit={onLoginAccount}
                        providerAuth={status.providerAuth}
                    />
                </CardContent>
            </Card>
        );
    }

    const publicProvider = isPublic(activeProvider);
    const issue = accountIssue(activeAccount);
    return (
        <Card className="panel">
            <CardHeader>
                <CardTitle>{providerLabel(activeProvider)}</CardTitle>
                <CardDescription>
                    {publicProvider ? "Public service" : activeAccount.display}
                </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-5">
                {issue ? <IssueNotice issue={issue} /> : null}
                <div className="grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
                    {publicProvider ? null : (
                        <>
                            <Metric
                                label="Subscription tier"
                                value={activeAccount.tier}
                            />
                            <SubscriptionMetric
                                subscriptionActive={
                                    activeAccount.subscriptionActive
                                }
                                subscriptionEndsAt={
                                    activeAccount.subscriptionEndsAt
                                }
                            />
                        </>
                    )}
                    <Metric
                        label="Last refresh"
                        title={formatTime(activeAccount.lastRefreshAt)}
                        value={formatCompactTime(activeAccount.lastRefreshAt)}
                    />
                    <Metric
                        label="Next refresh"
                        title={formatTime(activeAccount.nextRefreshAt)}
                        value={
                            activeAccount.refreshStatus === "needs_relogin"
                                ? "Paused"
                                : formatCompactTime(activeAccount.nextRefreshAt)
                        }
                    />
                </div>
            </CardContent>
            <CardFooter className={footerClassName}>
                <FormError message={providerError} />
                <div className="ml-auto flex flex-wrap justify-end gap-2">
                    {confirmRemoval === activeProvider ? (
                        <>
                            <Button
                                onClick={() => setConfirmRemoval("")}
                                size="sm"
                                variant="ghost"
                            >
                                Cancel
                            </Button>
                            <Button
                                disabled={providerBusy}
                                onClick={() =>
                                    void runProviderAction(() =>
                                        onRemoveProvider(activeProvider),
                                    )
                                }
                                size="sm"
                                variant="destructive"
                            >
                                Confirm removal
                            </Button>
                        </>
                    ) : (
                        <>
                            <Button
                                disabled={providerBusy || refreshing}
                                onClick={() =>
                                    void runProviderAction(() =>
                                        onRefreshProvider(activeProvider),
                                    )
                                }
                                size="sm"
                                variant="outline"
                            >
                                <RefreshCw
                                    className={
                                        providerBusy
                                            ? "size-4 animate-spin"
                                            : "size-4"
                                    }
                                />
                                Refresh
                            </Button>
                            <Button
                                disabled={providerBusy || refreshing}
                                onClick={() =>
                                    setConfirmRemoval(activeProvider)
                                }
                                size="sm"
                                variant="outline"
                            >
                                Remove
                            </Button>
                        </>
                    )}
                </div>
            </CardFooter>
        </Card>
    );
}

function ProviderTile({
    account,
    isPublic,
    nodeCount,
    onSelect,
    provider,
}: {
    account?: AccountSummary;
    isPublic: boolean;
    nodeCount: number;
    onSelect: () => void;
    provider: string;
}) {
    const issue = accountIssue(account);
    const issueText = issue?.tone === "err" ? "text-destructive" : "text-led-warn";
    return (
        <button
            className={`grid content-start gap-1.5 rounded-sm border bg-background/40 p-4 text-left transition-colors hover:border-primary/60 hover:bg-primary/[0.04] ${account ? "border-border" : "border-dashed border-border/80"}`}
            onClick={onSelect}
            type="button"
        >
            <span className="flex items-center justify-between gap-3">
                <strong
                    className={`font-sans uppercase tracking-[0.06em] ${account ? "" : "text-muted-foreground"}`}
                >
                    {providerLabel(provider)}
                </strong>
                <span
                    aria-hidden="true"
                    className={`led ${lampClass[accountTone(account)]}`}
                />
            </span>
            <span className="truncate text-xs text-muted-foreground">
                {!account
                    ? "Not added"
                    : isPublic
                      ? "Public service"
                      : account.display}
            </span>
            {account ? (
                issue ? (
                    <span className={`mt-1 text-xs font-medium ${issueText}`}>
                        {issue.summary}
                    </span>
                ) : (
                    <span className="mt-1 font-sans text-sm font-semibold uppercase tracking-[0.08em] text-primary/90">
                        {isPublic ? "" : `${account.tier} · `}
                        {nodeCount} {nodeCount === 1 ? "node" : "nodes"}
                    </span>
                )
            ) : null}
        </button>
    );
}

function IssueNotice({ issue }: { issue: AccountIssue }) {
    const tone =
        issue.tone === "err"
            ? "border-destructive/35 bg-destructive/10 text-destructive"
            : "border-led-warn/35 bg-led-warn/10 text-led-warn";
    return (
        <p
            className={`flex items-start gap-2.5 rounded-sm border px-3 py-2.5 text-[0.8125rem] leading-5 ${tone}`}
            role="status"
        >
            <span aria-hidden="true" className={`led ${lampClass[issue.tone]} mt-1.5`} />
            <span className="min-w-0">
                <strong className="font-semibold">{issue.summary}.</strong>{" "}
                <span className="text-foreground/80">{issue.action}</span>
            </span>
        </p>
    );
}
