import { LogOut, RefreshCw } from "lucide-react";
import type { NodeRecord, StatusResponse } from "@/types";
import { FormError } from "@/components/forms";
import { Metric } from "@/components/Metric";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { formatCompactTime, formatTime } from "@/lib/time";
import { ProviderCredentialsForm } from "./ProviderCredentialsForm";
import { SubscriptionMetric } from "./SubscriptionMetric";
import { providerLabel } from "./providers";
import type { useAccountViews } from "./useAccountViews";

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
    visibleNodes,
}: {
    accountView: ReturnType<typeof useAccountViews>;
    eligibleNodes: NodeRecord[];
    onLoginAccount: (provider: string, account: string, password: string) => Promise<void>;
    onRefreshAll: () => Promise<void>;
    onRefreshProvider: (provider: string) => Promise<void>;
    onRemoveProvider: (provider: string) => Promise<void>;
    onSignOutAll: () => Promise<void>;
    refreshing: boolean;
    status: StatusResponse;
    visibleNodes: NodeRecord[];
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
    const activeAccount =
        activeProvider === "all" ? undefined : accounts[activeProvider];
    const lastRefreshAt = formatTime(status.controlPlane.lastRefreshAt);
    const lastRefreshMetric = formatCompactTime(
        status.controlPlane.lastRefreshAt,
    );

    return (
    activeProvider === "all" ? (
        <Card className="panel">
            <CardHeader>
                <CardTitle>Providers</CardTitle>
                <CardDescription>
                    {Object.keys(accounts).length} of{" "}
                    {status.providers.length} providers connected.
                </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                {status.providers.map((provider) => {
                    const account = accounts[provider];
                    const providerNodes = eligibleNodes.filter(
                        (node) => node.provider === provider,
                    );
                    return (
                        <button
                            className="grid gap-2 rounded-sm border border-border bg-background/40 p-4 text-left transition-colors hover:border-primary/60 hover:bg-primary/[0.04]"
                            key={provider}
                            onClick={() => selectProvider(provider)}
                            type="button"
                        >
                            <span className="flex items-center justify-between gap-3">
                                <strong className="font-sans uppercase tracking-[0.06em]">
                                    {providerLabel(provider)}
                                </strong>
                                <span
                                    aria-hidden="true"
                                    className={`led ${account ? "led--ok" : ""}`}
                                />
                            </span>
                            <span className="text-xs text-muted-foreground">
                                {account
                                    ? account.display
                                    : "No account connected"}
                            </span>
                            <span className="font-sans text-sm font-semibold uppercase tracking-[0.08em] text-primary/90">
                                {account
                                    ? account.tier
                                    : "Not connected"}
                            </span>
                            <span className="text-[0.625rem] uppercase tracking-[0.18em] text-muted-foreground">
                                {providerNodes.length} eligible
                                nodes
                            </span>
                        </button>
                    );
                })}
            </CardContent>
            <CardFooter className="flex-wrap justify-between gap-3 border-t border-dashed border-border/70 pt-4 [&.border-t]:pt-4">
                <p className="min-w-0 text-xs leading-5 text-muted-foreground">
                    Manage your linked accounts.
                </p>
                <div className="flex w-full flex-wrap gap-2 sm:ml-auto sm:w-auto sm:justify-end">
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
                        className="border border-destructive/60 text-destructive hover:border-destructive hover:bg-destructive/10 hover:text-destructive"
                        disabled={
                            refreshing ||
                            providerBusy ||
                            Object.keys(accounts).length === 0
                        }
                        onClick={() => void onSignOutAll()}
                        size="sm"
                        variant="outline"
                    >
                        <LogOut />
                        Sign out all
                    </Button>
                </div>
            </CardFooter>
        </Card>
    ) : activeAccount ? (
        <Card className="panel">
            <CardHeader>
                <CardTitle>
                    {providerLabel(activeProvider)} account
                </CardTitle>
                <CardDescription>
                    {activeAccount.display}
                </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
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
                <Metric
                    label="Eligible nodes"
                    value={String(visibleNodes.length)}
                />
                <Metric
                    label="Last refresh"
                    title={lastRefreshAt}
                    value={lastRefreshMetric}
                />
            </CardContent>
            <CardFooter className="flex-wrap justify-between gap-3 border-t border-dashed border-border/70 pt-4 [&.border-t]:pt-4">
                <FormError message={providerError} />
                <div className="ml-auto flex flex-wrap justify-end gap-2">
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
                        Refresh provider
                    </Button>
                    {confirmRemoval === activeProvider ? (
                        <>
                            <Button
                                onClick={() =>
                                    setConfirmRemoval("")
                                }
                                size="sm"
                                variant="ghost"
                            >
                                Cancel
                            </Button>
                            <Button
                                disabled={providerBusy}
                                onClick={() =>
                                    void runProviderAction(() =>
                                        onRemoveProvider(
                                            activeProvider,
                                        ),
                                    )
                                }
                                size="sm"
                                variant="destructive"
                            >
                                Confirm removal
                            </Button>
                        </>
                    ) : (
                        <Button
                            disabled={providerBusy || refreshing}
                            onClick={() =>
                                setConfirmRemoval(activeProvider)
                            }
                            size="sm"
                            variant="outline"
                        >
                            Remove account
                        </Button>
                    )}
                </div>
            </CardFooter>
        </Card>
    ) : (
        <Card className="panel max-w-xl">
            <CardHeader>
                <CardTitle>
                    Connect {providerLabel(activeProvider)}
                </CardTitle>
            </CardHeader>
            <CardContent>
                <ProviderCredentialsForm
                    fixedProvider={activeProvider}
                    idPrefix={`add-${activeProvider}`}
                    onSubmit={onLoginAccount}
                />
            </CardContent>
        </Card>
    )
    );
}
