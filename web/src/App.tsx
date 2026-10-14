import { useMemo } from "react";
import type { Dispatch, ReactNode, SetStateAction } from "react";
import { LockKeyhole } from "lucide-react";
import type { ApiClient } from "./api";
import type { NodeRecord, StatusResponse } from "./types";
import { FormError } from "@/components/forms";
import { Button } from "@/components/ui/button";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AccessTokenCard } from "@/features/access/AccessTokenCard";
import { LoadingCard } from "@/features/access/LoadingCard";
import { useConsoleSession } from "@/features/access/useConsoleSession";
import { AccountPanel } from "@/features/accounts/AccountPanel";
import { accountIssue, accountTone, lampClass } from "@/features/accounts/accountHealth";
import { ProviderLoginCard } from "@/features/accounts/ProviderLoginCard";
import { providerLabel, providerLoginStates } from "@/features/accounts/providers";
import { StatusBadge, stateDetails } from "@/features/accounts/StatusBadge";
import { useAccountViews } from "@/features/accounts/useAccountViews";
import { NodeList } from "@/features/nodes/NodeList";
import { SubscriptionLinkCard } from "@/features/subscription/SubscriptionLinkCard";
import { useSubscriptionLink } from "@/features/subscription/useSubscriptionLink";
import { cn } from "@/lib/utils";

interface AppProps {
    api?: ApiClient;
}

export function App({ api: providedApi }: AppProps) {
    const {
        api,
        route,
        session,
        status,
        nodes,
        subscriptionURL,
        loadError,
        refreshing,
        setupAccess,
        loginAccess,
        loginAccount,
        loseAccessSession,
        lockConsole,
        getSessionRevision,
        setNodes,
        refreshAll,
        refreshProvider,
        removeProvider,
        signOutAll,
    } = useConsoleSession(providedApi);

    let content;
    if (session === "checking") {
        content = <LoadingCard />;
    } else if (session === "setup") {
        content = (
            <AccessTokenCard
                mode="setup"
                onSubmit={setupAccess}
                error={loadError}
            />
        );
    } else if (session === "access_login") {
        content = (
            <AccessTokenCard
                mode="login"
                onSubmit={loginAccess}
                error={loadError}
            />
        );
    } else if (
        !status ||
        route === "/signin" ||
        providerLoginStates[status.state]
    ) {
        content = (
            <ProviderLoginCard
                providers={status?.providers ?? []}
                providerAuth={status?.providerAuth ?? {}}
                onSubmit={loginAccount}
                error={loadError}
            />
        );
    } else {
        content = (
            <StatusConsole
                api={api}
                getSessionRevision={getSessionRevision}
                loadError={loadError}
                nodes={nodes}
                onAccessLost={loseAccessSession}
                onLockConsole={lockConsole}
                onNodesChange={setNodes}
                onLoginAccount={loginAccount}
                onRefreshAll={refreshAll}
                onRefreshProvider={refreshProvider}
                onRemoveProvider={removeProvider}
                onSignOutAll={signOutAll}
                refreshing={refreshing}
                status={status}
                subscriptionURL={subscriptionURL}
            />
        );
    }

    return <TooltipProvider delayDuration={150}>{content}</TooltipProvider>;
}

function StatusConsole({
    api,
    getSessionRevision,
    loadError,
    nodes,
    onAccessLost,
    onLockConsole,
    onLoginAccount,
    onNodesChange,
    onRefreshAll,
    onRefreshProvider,
    onRemoveProvider,
    onSignOutAll,
    refreshing,
    status,
    subscriptionURL,
}: {
    api: ApiClient;
    getSessionRevision: () => number;
    loadError: string;
    nodes: NodeRecord[];
    onAccessLost: () => void;
    onLockConsole: () => Promise<void>;
    onLoginAccount: (
        provider: string,
        fields: Record<string, string>,
    ) => Promise<void>;
    onNodesChange: Dispatch<SetStateAction<NodeRecord[]>>;
    onRefreshAll: () => Promise<void>;
    onRefreshProvider: (provider: string) => Promise<void>;
    onRemoveProvider: (provider: string) => Promise<void>;
    onSignOutAll: () => Promise<void>;
    refreshing: boolean;
    status: StatusResponse;
    subscriptionURL: string;
}) {
    const detail = stateDetails[status.state];
    const accounts = status.accounts ?? {};
    const eligibleNodes = useMemo(
        () => nodes.filter((node) => node.eligible),
        [nodes],
    );
    const subscriptionLink = useSubscriptionLink(eligibleNodes, subscriptionURL);
    const accountView = useAccountViews(status, subscriptionLink.resetFilters);
    const { activeProvider, selectProvider } = accountView;
    const visibleNodes =
        activeProvider === "all"
            ? eligibleNodes
            : eligibleNodes.filter((node) => node.provider === activeProvider);
    const activeAccount =
        activeProvider === "all" ? undefined : accounts[activeProvider];
    const issues = status.providers.flatMap((provider) => {
        const issue = accountIssue(accounts[provider]);
        return issue ? [{ provider, ...issue }] : [];
    });

    return (
        <main className="min-h-screen bg-background px-4 py-6 text-foreground sm:px-6 lg:px-10">
            <div className="boot mx-auto grid w-full max-w-6xl gap-6">
                <header className="border-b border-dashed border-border pb-5">
                    <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
                        <p className="glow font-sans text-sm font-bold uppercase tracking-[0.34em] text-primary">
                            Chinadapter
                        </p>
                        <p className="hidden text-[0.625rem] uppercase tracking-[0.24em] text-muted-foreground sm:block">
                            v{status.version}
                        </p>
                    </div>
                    <div className="mt-4 flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
                        <div className="min-w-0">
                            <div className="flex flex-nowrap items-center gap-2 sm:gap-3">
                                <h1 className="whitespace-nowrap font-sans text-xl font-semibold uppercase tracking-[0.04em] sm:text-2xl">
                                    Service status
                                </h1>
                                <StatusBadge detail={detail} />
                            </div>
                            {issues.length > 0 ? (
                                <ul
                                    aria-label="Provider problems"
                                    className="mt-3 grid gap-1"
                                >
                                    {issues.map((issue) => (
                                        <li key={issue.provider}>
                                            <button
                                                className="group flex min-w-0 items-baseline gap-2 text-left text-sm"
                                                onClick={() =>
                                                    selectProvider(issue.provider)
                                                }
                                                type="button"
                                            >
                                                <span
                                                    aria-hidden="true"
                                                    className={`led ${lampClass[issue.tone]} relative -top-px`}
                                                />
                                                <span className="font-sans font-semibold uppercase tracking-[0.06em] group-hover:text-primary">
                                                    {providerLabel(issue.provider)}
                                                </span>
                                                <span className="text-muted-foreground">
                                                    {issue.summary}. {issue.action}
                                                </span>
                                            </button>
                                        </li>
                                    ))}
                                </ul>
                            ) : status.state === "ready" ? null : (
                                <p className="mt-2 text-sm text-muted-foreground">
                                    {detail.message}
                                </p>
                            )}
                        </div>
                        <Button
                            aria-label="Lock console"
                            className="shrink-0 self-start"
                            onClick={() => void onLockConsole()}
                            size="sm"
                            variant="outline"
                        >
                            <LockKeyhole className="size-4" />
                            <span aria-hidden="true">Lock</span>
                        </Button>
                    </div>
                </header>

                <nav
                    aria-label="Console views"
                    className="flex gap-2 overflow-x-auto border-b border-border pb-3"
                >
                    <ViewTab
                        active={activeProvider === "all"}
                        onClick={() => selectProvider("all")}
                    >
                        Status
                    </ViewTab>
                    {status.providers.map((provider) => (
                        <ViewTab
                            active={activeProvider === provider}
                            key={provider}
                            onClick={() => selectProvider(provider)}
                        >
                            <span
                                aria-hidden="true"
                                className={`led ${lampClass[accountTone(accounts[provider])]}`}
                            />
                            {providerLabel(provider)}
                        </ViewTab>
                    ))}
                </nav>

                {loadError ? <FormError message={loadError} /> : null}

                <AccountPanel
                    accountView={accountView}
                    eligibleNodes={eligibleNodes}
                    onLoginAccount={onLoginAccount}
                    onRefreshAll={onRefreshAll}
                    onRefreshProvider={onRefreshProvider}
                    onRemoveProvider={onRemoveProvider}
                    onSignOutAll={onSignOutAll}
                    refreshing={refreshing}
                    status={status}
                />

                {activeProvider === "all" ? (
                    <SubscriptionLinkCard link={subscriptionLink} />
                ) : null}

                {activeAccount ? (
                    <NodeList
                        api={api}
                        getSessionRevision={getSessionRevision}
                        nodes={visibleNodes}
                        onAccessLost={onAccessLost}
                        onNodesChange={onNodesChange}
                    />
                ) : null}
            </div>
        </main>
    );
}

// Selected tabs are tinted rather than filled so their status lamp stays visible.
function ViewTab({
    active,
    children,
    onClick,
}: {
    active: boolean;
    children: ReactNode;
    onClick: () => void;
}) {
    return (
        <Button
            aria-pressed={active}
            className={cn(
                "shrink-0",
                active &&
                    "border-primary/70 bg-primary/10 text-primary hover:bg-primary/15",
            )}
            onClick={onClick}
            size="sm"
            variant="outline"
        >
            {children}
        </Button>
    );
}
