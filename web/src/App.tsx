import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Dispatch, FormEvent, ReactNode, SetStateAction } from "react";
import {
    ChevronRight,
    Copy,
    Gauge,
    Info,
    LoaderCircle,
    LockKeyhole,
    LogOut,
    RefreshCw,
} from "lucide-react";
import { ApiClient, ApiError } from "./api";
import type {
    EventMessage,
    NodeDetails,
    NodeHealth,
    NodeRecord,
    ServiceState,
    StatusResponse,
} from "./types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
    Card,
    CardAction,
    CardContent,
    CardDescription,
    CardFooter,
    CardHeader,
    CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
    Popover,
    PopoverContent,
    PopoverTrigger,
} from "@/components/ui/popover";
import {
    Tooltip,
    TooltipContent,
    TooltipProvider,
    TooltipTrigger,
} from "@/components/ui/tooltip";

const providerLoginStates: Partial<Record<ServiceState, true>> = {
    signed_out: true,
    expired: true,
};

const providerLabels: Record<string, string> = {
    kuaifan: "KuaiFan",
    quickfox: "QuickFox",
};

const selectClassName =
    "flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm shadow-xs outline-none transition-[color,box-shadow] focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50";

function providerLabel(provider: string): string {
    return providerLabels[provider] ?? provider;
}

type Route = "/" | "/signin";
type SessionState = "checking" | "setup" | "access_login" | "available";

interface AppProps {
    api?: ApiClient;
}

interface StatusDetail {
    label: string;
    message: string;
    tone: "ready" | "working" | "warning" | "danger" | "neutral";
}

const stateDetails: Record<ServiceState, StatusDetail> = {
    signed_out: {
        label: "Signed out",
        message: "Connect an account to load nodes.",
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
        message: "Connect your account again.",
        tone: "danger",
    },
    error: {
        label: "Service error",
        message: "Service status could not be completed.",
        tone: "danger",
    },
};

const groupNameCollator = new Intl.Collator(["zh-CN-u-co-pinyin", "en"], {
    numeric: true,
    sensitivity: "base",
});
const namedGroupPriorities: Record<string, number> = {
    优选直连线路: 1,
    "音乐/视频APP专线": 2,
};

function groupPriority(group: string): number {
    const namedPriority = namedGroupPriorities[group];
    if (namedPriority !== undefined) return namedPriority;
    return /➩\s*中国(?:大陆)?$/u.test(group) ? 3 : 0;
}

function compareGroupNames(left: string, right: string): number {
    return (
        groupPriority(left) - groupPriority(right) ||
        groupNameCollator.compare(left, right)
    );
}

function routeFromLocation(): Route {
    return window.location.pathname === "/signin" ? "/signin" : "/";
}

function replaceRoute(route: Route): void {
    if (window.location.pathname !== route)
        window.history.replaceState(null, "", route);
    window.dispatchEvent(new PopStateEvent("popstate"));
}

function isSessionProblem(error: unknown): boolean {
    return (
        error instanceof ApiError &&
        (error.problem.status === 401 || error.problem.status === 403)
    );
}

function describeError(error: unknown): string {
    if (error instanceof ApiError) {
        if (error.problem.code === "rate_limited")
            return "Too many attempts. Wait a moment and try again.";
        if (error.problem.code === "invalid_access_token")
            return "That access token was not accepted.";
        if (error.problem.code === "invalid_next_access_token")
            return "Use a different access token of 16–128 bytes.";
        if (error.problem.code === "login_rejected")
            return "The provider rejected that email or password.";
        return error.problem.detail || error.problem.title;
    }
    return "The local service did not complete that request.";
}

function formatTime(value?: string): string {
    if (!value) return "—";
    const time = new Date(value);
    return Number.isNaN(time.getTime())
        ? "—"
        : time.toLocaleString(undefined, {
              dateStyle: "medium",
              timeStyle: "short",
          });
}

function formatCompactTime(value?: string): string {
    if (!value) return "—";
    const time = new Date(value);
    if (Number.isNaN(time.getTime())) return "—";
    const formatted = time.toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "numeric",
        minute: "2-digit",
    });
    return formatted
        .replace(/,\s*/u, " · ")
        .replace(/\s+(AM|PM)$/u, "\u00a0$1");
}

async function copyText(value: string): Promise<boolean> {
    try {
        if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(value);
            return true;
        }
    } catch {
        // Fall through to the legacy copy command for non-secure LAN origins.
    }

    const textArea = document.createElement("textarea");
    textArea.value = value;
    textArea.setAttribute("readonly", "");
    textArea.style.position = "fixed";
    textArea.style.opacity = "0";
    textArea.style.pointerEvents = "none";
    document.body.append(textArea);
    textArea.select();
    try {
        return document.execCommand("copy");
    } catch {
        return false;
    } finally {
        textArea.remove();
    }
}

interface SubscriptionValidity {
    summary: string;
    endsAt?: string;
}

function describeSubscriptionValidity(
    subscriptionActive: boolean,
    subscriptionEndsAt?: string,
) {
    if (!subscriptionActive) return { summary: "Free" };
    if (!subscriptionEndsAt)
        return { summary: "Active · End date unavailable" };

    const endTime = new Date(subscriptionEndsAt);
    if (Number.isNaN(endTime.getTime()))
        return { summary: "Active · End date unavailable" };

    const remaining = endTime.getTime() - Date.now();
    const endsAt = formatTime(subscriptionEndsAt);
    if (remaining <= 0) return { summary: "Expired", endsAt };
    if (remaining < 60 * 60 * 1000)
        return { summary: "Active · Valid for less than an hour", endsAt };

    const hours = Math.ceil(remaining / (60 * 60 * 1000));
    if (hours < 24)
        return {
            summary: `Active · Valid for ${hours} ${hours === 1 ? "hour" : "hours"}`,
            endsAt,
        };

    const days = Math.ceil(remaining / (24 * 60 * 60 * 1000));
    return {
        summary: `Active · Valid for ${days} ${days === 1 ? "day" : "days"}`,
        endsAt,
    };
}

function formatLatency(value?: number): string {
    return typeof value === "number" ? `${value} ms` : "—";
}

function probeFailureLabel(error: unknown): string {
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

function healthLabel(health: NodeHealth): string {
    return health.slice(0, 1).toUpperCase() + health.slice(1);
}

export function App({ api: providedApi }: AppProps) {
    const apiRef = useRef<ApiClient>(providedApi ?? new ApiClient());
    const api = apiRef.current;
    const [route, setRoute] = useState<Route>(routeFromLocation);
    const [session, setSession] = useState<SessionState>("checking");
    const [status, setStatus] = useState<StatusResponse | null>(null);
    const [nodes, setNodes] = useState<NodeRecord[]>([]);
    const [subscriptionURL, setSubscriptionURL] = useState("");
    const [loadError, setLoadError] = useState("");
    const [refreshing, setRefreshing] = useState(false);
    const sessionRevision = useRef(0);
    const reloadWork = useRef({
        scheduled: false,
        running: false,
        queued: false,
        revision: 0,
    });
    const nextSSEFailureReloadAt = useRef(0);

    const clearProviderData = useCallback(() => {
        setStatus(null);
        setNodes([]);
        setSubscriptionURL("");
        setRefreshing(false);
    }, []);

    const clearConsoleData = useCallback(() => {
        clearProviderData();
        setLoadError("");
    }, [clearProviderData]);

    const loseAccessSession = useCallback(() => {
        sessionRevision.current += 1;
        reloadWork.current.queued = false;
        api.clearSession();
        clearConsoleData();
        setSession("access_login");
        replaceRoute("/");
    }, [api, clearConsoleData]);

    const loadAuthenticatedData =
        useCallback(async (): Promise<StatusResponse | null> => {
            const revision = sessionRevision.current;
            try {
                const nextStatus = await api.status();
                if (revision !== sessionRevision.current) return null;

                if (providerLoginStates[nextStatus.state]) {
                    setStatus(nextStatus);
                    setNodes([]);
                    setSubscriptionURL("");
                    setLoadError("");
                    return nextStatus;
                }

                setStatus(nextStatus);
                setLoadError("");

                const [nextNodes, nextSubscription] = await Promise.all([
                    api.nodes(),
                    api.subscriptionURL(),
                ]);
                if (revision !== sessionRevision.current) return null;

                setNodes(nextNodes.nodes);
                setSubscriptionURL(nextSubscription.url);
                return nextStatus;
            } catch (error) {
                if (revision !== sessionRevision.current) return null;
                if (isSessionProblem(error)) {
                    loseAccessSession();
                    return null;
                }
                setLoadError(describeError(error));
                return null;
            }
        }, [api, loseAccessSession]);

    const queueAuthenticatedReload = useCallback(() => {
        const work = reloadWork.current;
        work.queued = true;
        work.revision = sessionRevision.current;
        if (work.scheduled || work.running) return;

        work.scheduled = true;
        queueMicrotask(async () => {
            work.scheduled = false;
            while (work.queued && work.revision === sessionRevision.current) {
                work.queued = false;
                work.running = true;
                const revision = work.revision;
                await loadAuthenticatedData();
                work.running = false;
                if (revision !== sessionRevision.current) {
                    work.queued = false;
                    return;
                }
            }
        });
    }, [loadAuthenticatedData]);

    useEffect(() => {
        const updateRoute = () => setRoute(routeFromLocation());
        window.addEventListener("popstate", updateRoute);
        return () => window.removeEventListener("popstate", updateRoute);
    }, []);

    useEffect(() => {
        if (window.location.pathname !== route) replaceRoute(route);
    }, [route]);

    useEffect(() => {
        if (session !== "available" && route !== "/") replaceRoute("/");
    }, [route, session]);

    useEffect(() => {
        if (session !== "available") return;
        const needsProviderLogin =
            !status || Boolean(providerLoginStates[status.state]);
        if (needsProviderLogin && route !== "/signin") replaceRoute("/signin");
        if (!needsProviderLogin && route === "/signin") replaceRoute("/");
    }, [route, session, status]);

    useEffect(() => {
        let active = true;
        api.accessStatus()
            .then((access) => {
                if (!active) return;
                if (!access.initialized) {
                    setSession("setup");
                    return;
                }
                if (!access.authenticated) {
                    setSession("access_login");
                    return;
                }
                sessionRevision.current += 1;
                setSession("available");
                queueAuthenticatedReload();
            })
            .catch((error: unknown) => {
                if (!active) return;
                setLoadError(describeError(error));
                setSession("access_login");
            });
        return () => {
            active = false;
        };
    }, [api, queueAuthenticatedReload]);

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

    const completeAccess = useCallback(() => {
        sessionRevision.current += 1;
        setLoadError("");
        setSession("available");
        replaceRoute("/");
        queueAuthenticatedReload();
    }, [queueAuthenticatedReload]);

    const setupAccess = async (token: string): Promise<void> => {
        await api.setupAccess(token);
        completeAccess();
    };

    const loginAccess = async (token: string): Promise<void> => {
        await api.loginAccess(token);
        completeAccess();
    };

    const loginAccount = async (
        provider: string,
        account: string,
        password: string,
    ): Promise<void> => {
        const revision = sessionRevision.current;
        await api.login(provider, account, password);
        await loadAuthenticatedData();
        if (revision === sessionRevision.current) replaceRoute("/");
    };

    const mutateProvider = async (
        provider: string,
        operation: (provider: string) => Promise<void>,
    ): Promise<void> => {
        const revision = sessionRevision.current;
        setRefreshing(true);
        try {
            await operation(provider);
            if (revision === sessionRevision.current)
                await loadAuthenticatedData();
        } catch (error) {
            if (revision === sessionRevision.current && isSessionProblem(error))
                loseAccessSession();
            throw error;
        } finally {
            if (revision === sessionRevision.current) setRefreshing(false);
        }
    };

    const refreshProvider = (provider: string) =>
        mutateProvider(provider, (id) => api.refresh(id));

    const signOutAll = async (): Promise<void> => {
        const revision = sessionRevision.current;
        const linkedProviders = Object.keys(status?.accounts ?? {}).sort(
            groupNameCollator.compare,
        );
        if (linkedProviders.length === 0) return;

        setRefreshing(true);
        setLoadError("");
        try {
            for (const provider of linkedProviders)
                await api.logoutAccount(provider);
            if (revision === sessionRevision.current)
                await loadAuthenticatedData();
        } catch (error) {
            if (revision !== sessionRevision.current) return;
            if (isSessionProblem(error)) {
                loseAccessSession();
                return;
            }
            setLoadError(describeError(error));
        } finally {
            if (revision === sessionRevision.current) setRefreshing(false);
        }
    };
    const removeProvider = (provider: string) =>
        mutateProvider(provider, (id) => api.logoutAccount(id));

    const lockConsole = async (): Promise<void> => {
        const revision = ++sessionRevision.current;
        reloadWork.current.queued = false;
        clearConsoleData();
        setSession("access_login");
        replaceRoute("/");
        try {
            await api.lockConsole();
        } catch (error) {
            if (
                revision === sessionRevision.current &&
                !isSessionProblem(error)
            )
                setLoadError(describeError(error));
        } finally {
            api.clearSession();
        }
    };

    const refreshAll = async (): Promise<void> => {
        const revision = sessionRevision.current;
        setRefreshing(true);
        setLoadError("");
        try {
            await api.refresh("");
            if (revision === sessionRevision.current)
                await loadAuthenticatedData();
        } catch (error) {
            if (revision !== sessionRevision.current) return;
            if (isSessionProblem(error)) {
                loseAccessSession();
                return;
            }
            setLoadError(describeError(error));
        } finally {
            if (revision === sessionRevision.current) setRefreshing(false);
        }
    };

    const getSessionRevision = useCallback(() => sessionRevision.current, []);

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

function AuthCardShell({ children }: { children: ReactNode }) {
    return (
        <main className="flex min-h-screen items-center justify-center bg-background px-4 py-10 text-foreground">
            <div className="boot w-full max-w-md">
                <div className="mb-5 flex items-end justify-between gap-4 px-1">
                    <div>
                        <p className="glow font-sans text-lg font-bold uppercase tracking-[0.34em] text-primary">
                            Kfadapter
                        </p>
                        <p className="mt-1 text-[0.625rem] uppercase tracking-[0.24em] text-muted-foreground">
                            Local control plane
                        </p>
                    </div>
                    <div
                        aria-hidden="true"
                        className="mb-1.5 flex items-center gap-1.5"
                    >
                        <span className="led led--ok" />
                        <span className="led led--warn led--pulse" />
                        <span className="led" />
                    </div>
                </div>
                <Card className="panel w-full">
                    {children}
                    <CardFooter className="justify-between border-t border-dashed border-border/70 pt-4 text-[0.625rem] uppercase tracking-[0.22em] text-muted-foreground [&.border-t]:pt-4">
                        <span>Console access</span>
                        <span aria-hidden="true">▪ ▪ ▪</span>
                    </CardFooter>
                </Card>
            </div>
        </main>
    );
}

function LoadingCard() {
    return (
        <AuthCardShell>
            <CardHeader>
                <h1 className="flex items-center gap-2.5 font-sans text-lg font-semibold uppercase tracking-[0.05em]">
                    <LoaderCircle className="size-5 animate-spin text-primary" />
                    Opening kfadapter
                </h1>
                <CardDescription>Checking console access.</CardDescription>
            </CardHeader>
        </AuthCardShell>
    );
}

function AccessTokenCard({
    mode,
    onSubmit,
    error,
}: {
    mode: "setup" | "login";
    onSubmit: (token: string) => Promise<void>;
    error: string;
}) {
    const [token, setToken] = useState("");
    const [confirmation, setConfirmation] = useState("");
    const [submitting, setSubmitting] = useState(false);
    const [localError, setLocalError] = useState("");
    const isSetup = mode === "setup";

    const clearFields = () => {
        setToken("");
        setConfirmation("");
    };

    const submit = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        const submittedToken = token.trim();
        const submittedConfirmation = confirmation.trim();
        clearFields();

        const tokenBytes = new TextEncoder().encode(submittedToken).byteLength;
        if (tokenBytes < 16 || tokenBytes > 128) {
            setLocalError("That access token is too short or too long.");
            return;
        }
        if (isSetup && submittedToken !== submittedConfirmation) {
            setLocalError("The access tokens do not match.");
            return;
        }

        setSubmitting(true);
        setLocalError("");
        try {
            await onSubmit(submittedToken);
        } catch (requestError) {
            setLocalError(describeError(requestError));
        } finally {
            clearFields();
            setSubmitting(false);
        }
    };

    return (
        <AuthCardShell>
            <CardHeader>
                <h1 className="font-sans text-xl font-semibold uppercase tracking-[0.05em]">
                    {isSetup ? "Create console access" : "Unlock console"}
                </h1>
                <CardDescription>
                    {isSetup
                        ? "Set an access token for this console."
                        : "Enter your access token to continue."}
                </CardDescription>
            </CardHeader>
            <CardContent>
                <form className="grid gap-4" noValidate onSubmit={submit}>
                    <FormError message={localError || error} />
                    <Field label="Access token" name="access-token">
                        <Input
                            autoComplete="off"
                            id="access-token"
                            name="access-token"
                            onChange={(event) =>
                                setToken(event.currentTarget.value)
                            }
                            type="password"
                            value={token}
                        />
                    </Field>
                    {isSetup ? (
                        <Field
                            label="Confirm access token"
                            name="access-token-confirmation"
                        >
                            <Input
                                autoComplete="off"
                                id="access-token-confirmation"
                                name="access-token-confirmation"
                                onChange={(event) =>
                                    setConfirmation(event.currentTarget.value)
                                }
                                type="password"
                                value={confirmation}
                            />
                        </Field>
                    ) : null}
                    <Button
                        className="mt-2 w-full"
                        disabled={submitting}
                        type="submit"
                    >
                        {submitting ? (
                            <>
                                <LoaderCircle className="size-4 animate-spin" />
                                Checking
                            </>
                        ) : isSetup ? (
                            "Create access"
                        ) : (
                            "Continue"
                        )}
                    </Button>
                </form>
            </CardContent>
        </AuthCardShell>
    );
}

function ProviderLoginCard({
    onSubmit,
    error,
    providers,
}: {
    onSubmit: (
        provider: string,
        account: string,
        password: string,
    ) => Promise<void>;
    error: string;
    providers: string[];
}) {
    return (
        <AuthCardShell>
            <CardHeader>
                <h1 className="font-sans text-xl font-semibold uppercase tracking-[0.05em]">
                    Connect account
                </h1>
                <CardDescription>
                    Choose a provider before entering account credentials.
                </CardDescription>
            </CardHeader>
            <CardContent>
                <ProviderCredentialsForm
                    error={error}
                    idPrefix="initial"
                    onSubmit={onSubmit}
                    providers={providers}
                />
            </CardContent>
        </AuthCardShell>
    );
}

function ProviderCredentialsForm({
    error,
    fixedProvider,
    idPrefix,
    onSubmit,
    providers = [],
}: {
    error?: string;
    fixedProvider?: string;
    idPrefix: string;
    onSubmit: (
        provider: string,
        account: string,
        password: string,
    ) => Promise<void>;
    providers?: string[];
}) {
    const [account, setAccount] = useState("");
    const [password, setPassword] = useState("");
    const [provider, setProvider] = useState(fixedProvider ?? "");
    const [submitting, setSubmitting] = useState(false);
    const [localError, setLocalError] = useState("");
    const accountID = `${idPrefix}-account`;
    const passwordID = `${idPrefix}-password`;
    const providerID = `${idPrefix}-provider`;

    const submit = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        const selectedProvider = fixedProvider ?? provider;
        const email = account.trim();
        const submittedPassword = password;
        setPassword("");
        if (!selectedProvider) {
            setLocalError(
                "Choose a provider before entering account credentials.",
            );
            return;
        }
        if (!email || !submittedPassword) {
            setLocalError("Enter your email and password.");
            return;
        }
        setSubmitting(true);
        setLocalError("");
        try {
            await onSubmit(selectedProvider, email, submittedPassword);
            setAccount("");
        } catch (requestError) {
            setLocalError(describeError(requestError));
        } finally {
            setPassword("");
            setSubmitting(false);
        }
    };

    return (
        <form className="grid gap-4" noValidate onSubmit={submit}>
            <FormError message={localError || error || ""} />
            {fixedProvider ? null : (
                <Field label="Provider" name={providerID}>
                    <select
                        className={selectClassName}
                        id={providerID}
                        name="provider"
                        onChange={(event) =>
                            setProvider(event.currentTarget.value)
                        }
                        value={provider}
                    >
                        <option value="">Choose provider…</option>
                        {providers.map((id) => (
                            <option key={id} value={id}>
                                {providerLabel(id)}
                            </option>
                        ))}
                    </select>
                </Field>
            )}
            <Field label="Email" name={accountID}>
                <Input
                    autoComplete="off"
                    id={accountID}
                    inputMode="email"
                    name="account"
                    onChange={(event) => setAccount(event.currentTarget.value)}
                    type="email"
                    value={account}
                />
            </Field>
            <Field label="Password" name={passwordID}>
                <Input
                    autoComplete="off"
                    id={passwordID}
                    name="password"
                    onChange={(event) => setPassword(event.currentTarget.value)}
                    type="password"
                    value={password}
                />
            </Field>
            <Button className="mt-2 w-full" disabled={submitting} type="submit">
                {submitting ? (
                    <>
                        <LoaderCircle className="size-4 animate-spin" />
                        Signing in
                    </>
                ) : fixedProvider ? (
                    `Connect ${providerLabel(fixedProvider)}`
                ) : (
                    "Sign in"
                )}
            </Button>
        </form>
    );
}

function Field({
    label,
    name,
    children,
}: {
    label: string;
    name: string;
    children: ReactNode;
}) {
    return (
        <label className="grid gap-2" htmlFor={name}>
            <span className="text-[0.65rem] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
                {label}
            </span>
            {children}
        </label>
    );
}

function FormError({ message }: { message: string }) {
    return message ? (
        <p
            className="flex items-start gap-2.5 rounded-sm border border-destructive/35 bg-destructive/10 px-3 py-2.5 text-[0.8125rem] leading-5 text-destructive"
            role="alert"
        >
            <span
                aria-hidden="true"
                className="led led--err led--pulse mt-1.5"
            />
            <span className="min-w-0">{message}</span>
        </p>
    ) : null;
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
        account: string,
        password: string,
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
    const [activeProvider, setActiveProvider] = useState("all");
    const [copyMessage, setCopyMessage] = useState("");
    const [filterProvider, setFilterProvider] = useState("");
    const [filterGroup, setFilterGroup] = useState("");
    const [filterName, setFilterName] = useState("");
    const [providerError, setProviderError] = useState("");
    const [providerBusy, setProviderBusy] = useState(false);
    const [confirmRemoval, setConfirmRemoval] = useState("");
    const copyResetTimer = useRef<number | undefined>(undefined);

    const accounts = status.accounts ?? {};
    const eligibleNodes = useMemo(
        () => nodes.filter((node) => node.eligible),
        [nodes],
    );
    const visibleNodes =
        activeProvider === "all"
            ? eligibleNodes
            : eligibleNodes.filter((node) => node.provider === activeProvider);
    const nodeProviders = useMemo(
        () =>
            [...new Set(eligibleNodes.map((node) => node.provider))].sort(
                groupNameCollator.compare,
            ),
        [eligibleNodes],
    );
    const filterGroups = useMemo(
        () =>
            [
                ...new Set(
                    eligibleNodes
                        .filter(
                            (node) =>
                                !filterProvider ||
                                node.provider === filterProvider,
                        )
                        .map((node) => node.group),
                ),
            ].sort(compareGroupNames),
        [eligibleNodes, filterProvider],
    );

    useEffect(() => {
        if (filterGroup && !filterGroups.includes(filterGroup))
            setFilterGroup("");
    }, [filterGroup, filterGroups]);

    useEffect(() => {
        if (
            activeProvider !== "all" &&
            !status.providers.includes(activeProvider)
        )
            setActiveProvider("all");
    }, [activeProvider, status.providers]);

    const filteredSubscriptionURL = useMemo(() => {
        if (!subscriptionURL) return "";
        try {
            const next = new URL(subscriptionURL);
            if (filterProvider)
                next.searchParams.set("provider", filterProvider);
            if (filterGroup) next.searchParams.set("group", filterGroup);
            if (filterName.trim())
                next.searchParams.set("name", filterName.trim());
            return next.toString();
        } catch {
            return subscriptionURL;
        }
    }, [filterGroup, filterName, filterProvider, subscriptionURL]);

    const clearCopyMessage = () => {
        clearTimeout(copyResetTimer.current);
        copyResetTimer.current = undefined;
        setCopyMessage("");
    };

    useEffect(() => () => clearTimeout(copyResetTimer.current), []);
    useEffect(() => {
        clearCopyMessage();
    }, [filteredSubscriptionURL]);

    const selectProvider = (provider: string) => {
        setActiveProvider(provider);
        setProviderError("");
        setConfirmRemoval("");
        if (provider !== "all") {
            clearCopyMessage();
            setFilterProvider("");
            setFilterGroup("");
            setFilterName("");
        }
    };

    const copySubscription = async () => {
        if (!filteredSubscriptionURL) return;
        clearCopyMessage();
        setCopyMessage(
            (await copyText(filteredSubscriptionURL))
                ? "Link copied."
                : "Copy is unavailable.",
        );
        copyResetTimer.current = window.setTimeout(
            () => setCopyMessage(""),
            2500,
        );
    };

    const runProviderAction = async (action: () => Promise<void>) => {
        setProviderBusy(true);
        setProviderError("");
        try {
            await action();
            setConfirmRemoval("");
        } catch (error) {
            if (!isSessionProblem(error))
                setProviderError(describeError(error));
        } finally {
            setProviderBusy(false);
        }
    };

    const activeAccount =
        activeProvider === "all" ? undefined : accounts[activeProvider];
    const lastRefreshAt = formatTime(status.controlPlane.lastRefreshAt);
    const lastRefreshMetric = formatCompactTime(
        status.controlPlane.lastRefreshAt,
    );

    return (
        <main className="min-h-screen bg-background px-4 py-6 text-foreground sm:px-6 lg:px-10">
            <div className="boot mx-auto grid w-full max-w-6xl gap-6">
                <header className="border-b border-dashed border-border pb-5">
                    <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
                        <p className="glow font-sans text-sm font-bold uppercase tracking-[0.34em] text-primary">
                            Kfadapter
                        </p>
                        <p className="hidden text-[0.625rem] uppercase tracking-[0.24em] text-muted-foreground sm:block">
                            Local control plane · v{status.version}
                        </p>
                    </div>
                    <div className="mt-4 flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
                        <div>
                            <div className="flex flex-nowrap items-center gap-2 sm:gap-3">
                                <h1 className="whitespace-nowrap font-sans text-xl font-semibold uppercase tracking-[0.04em] sm:text-2xl">
                                    Service status
                                </h1>
                                <StatusBadge detail={detail} />
                            </div>
                            {status.state === "ready" ? null : (
                                <p className="mt-2 text-sm text-muted-foreground">
                                    {detail.message}
                                </p>
                            )}
                        </div>
                        <div className="flex flex-nowrap items-center gap-1 sm:gap-2">
                            <Button
                                aria-label="Lock console"
                                onClick={() => void onLockConsole()}
                                size="sm"
                                variant="outline"
                            >
                                <LockKeyhole className="size-4" />
                                <span aria-hidden="true" className="sm:hidden">
                                    Lock
                                </span>
                                <span
                                    aria-hidden="true"
                                    className="hidden sm:inline"
                                >
                                    Lock console
                                </span>
                            </Button>
                        </div>
                    </div>
                </header>

                <nav
                    aria-label="Console views"
                    className="flex gap-2 overflow-x-auto border-b border-border pb-3"
                >
                    <Button
                        aria-pressed={activeProvider === "all"}
                        onClick={() => selectProvider("all")}
                        size="sm"
                        variant={
                            activeProvider === "all" ? "default" : "outline"
                        }
                    >
                        Status
                    </Button>
                    {status.providers.map((provider) => (
                        <Button
                            aria-pressed={activeProvider === provider}
                            className="shrink-0"
                            key={provider}
                            onClick={() => selectProvider(provider)}
                            size="sm"
                            variant={
                                activeProvider === provider
                                    ? "default"
                                    : "outline"
                            }
                        >
                            <span
                                aria-hidden="true"
                                className={`led ${accounts[provider] ? "led--ok" : ""}`}
                            />
                            {providerLabel(provider)}
                        </Button>
                    ))}
                </nav>

                {loadError ? <FormError message={loadError} /> : null}

                {activeProvider === "all" ? (
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
                )}

                {activeProvider === "all" ? (
                    <section className="grid gap-4 md:grid-cols-[0.9fr_1.5fr]">
                        <Card className="panel">
                            <CardHeader>
                                <CardTitle>Service</CardTitle>
                            </CardHeader>
                            <CardContent className="grid gap-5 sm:grid-cols-2 md:grid-cols-1 lg:grid-cols-2">
                                <Metric
                                    label="Accounts"
                                    value={`${Object.keys(accounts).length} / ${status.providers.length}`}
                                />
                                <Metric
                                    label="Available nodes"
                                    value={`${status.nodes.eligible} / ${status.nodes.total}`}
                                />
                            </CardContent>
                            <CardFooter className="gap-2 text-xs text-muted-foreground">
                                <span
                                    aria-hidden="true"
                                    className={`led ${refreshing ? "led--warn led--pulse" : "led--ok"}`}
                                />
                                <span
                                    className="min-w-0 truncate"
                                    title={`Updated ${formatTime(status.controlPlane.lastRefreshAt)}`}
                                >
                                    Updated{" "}
                                    {formatTime(
                                        status.controlPlane.lastRefreshAt,
                                    )}
                                </span>
                            </CardFooter>
                        </Card>

                        <Card className="panel">
                            <CardHeader>
                                <CardTitle>Subscription link</CardTitle>
                                <CardAction>
                                    <Tooltip>
                                        <TooltipTrigger asChild>
                                            <Button
                                                aria-label="Copy subscription link"
                                                disabled={
                                                    !filteredSubscriptionURL
                                                }
                                                onClick={() =>
                                                    void copySubscription()
                                                }
                                                size="icon"
                                                variant="ghost"
                                            >
                                                <Copy className="size-4" />
                                            </Button>
                                        </TooltipTrigger>
                                        <TooltipContent>
                                            Copy filtered link
                                        </TooltipContent>
                                    </Tooltip>
                                </CardAction>
                            </CardHeader>
                            <CardContent className="grid gap-3">
                                <div className="grid gap-3 sm:grid-cols-3">
                                    <Field
                                        label="Provider"
                                        name="subscription-provider"
                                    >
                                        <select
                                            className={selectClassName}
                                            id="subscription-provider"
                                            onChange={(event) =>
                                                setFilterProvider(
                                                    event.currentTarget.value,
                                                )
                                            }
                                            value={filterProvider}
                                        >
                                            <option value="">
                                                All providers
                                            </option>
                                            {nodeProviders.map((provider) => (
                                                <option
                                                    key={provider}
                                                    value={provider}
                                                >
                                                    {providerLabel(provider)}
                                                </option>
                                            ))}
                                        </select>
                                    </Field>
                                    <Field
                                        label="Group"
                                        name="subscription-group"
                                    >
                                        <select
                                            className={selectClassName}
                                            id="subscription-group"
                                            onChange={(event) =>
                                                setFilterGroup(
                                                    event.currentTarget.value,
                                                )
                                            }
                                            value={filterGroup}
                                        >
                                            <option value="">All groups</option>
                                            {filterGroups.map((group) => (
                                                <option
                                                    key={group}
                                                    value={group}
                                                >
                                                    {group}
                                                </option>
                                            ))}
                                        </select>
                                    </Field>
                                    <Field
                                        label="Node name"
                                        name="subscription-name"
                                    >
                                        <Input
                                            id="subscription-name"
                                            onChange={(event) =>
                                                setFilterName(
                                                    event.currentTarget.value,
                                                )
                                            }
                                            placeholder="Contains…"
                                            value={filterName}
                                        />
                                    </Field>
                                </div>
                                <code
                                    aria-busy={!filteredSubscriptionURL}
                                    className="readout block break-all rounded-sm border border-border/70 px-3 py-2.5 text-xs leading-5 text-primary/90"
                                >
                                    {filteredSubscriptionURL || (
                                        <span className="animate-pulse text-muted-foreground">
                                            Loading link…
                                        </span>
                                    )}
                                </code>
                                <p
                                    aria-live="polite"
                                    className="min-h-5 text-xs text-muted-foreground"
                                    role="status"
                                >
                                    {copyMessage}
                                </p>
                            </CardContent>
                        </Card>
                    </section>
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

function StatusBadge({ detail }: { detail: StatusDetail }) {
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

function Metric({
    label,
    title,
    value,
}: {
    label: string;
    title?: string;
    value: string;
}) {
    return (
        <div className="min-w-0 border-l border-primary/40 pl-3">
            <p className="text-[0.65rem] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
                {label}
            </p>
            <p
                className="mt-1.5 break-words font-sans text-2xl font-semibold leading-tight tabular-nums"
                title={title}
            >
                {value}
            </p>
        </div>
    );
}

function SubscriptionMetric({
    subscriptionActive,
    subscriptionEndsAt,
}: {
    subscriptionActive: boolean;
    subscriptionEndsAt?: string;
}) {
    const validity = describeSubscriptionValidity(
        subscriptionActive,
        subscriptionEndsAt,
    );
    return (
        <div className="border-l border-primary/40 pl-3">
            <p className="text-[0.65rem] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
                Subscription
            </p>
            <p className="mt-1.5 break-words font-sans text-lg font-semibold leading-tight tabular-nums">
                {validity.summary}
            </p>
            {validity.endsAt ? (
                <p
                    className="mt-1 text-xs text-muted-foreground"
                    title={validity.endsAt}
                >
                    Ends {validity.endsAt}
                </p>
            ) : null}
        </div>
    );
}

function NodeList({
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
    const [probingAll, setProbingAll] = useState(false);
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

    const probeAll = async () => {
        if (nodes.length === 0) return;
        const revision = getSessionRevision();
        setProbingAll(true);
        try {
            for (const [, members] of groupedNodes) {
                for (const node of members) {
                    if (!active.current || revision !== getSessionRevision())
                        return;
                    try {
                        const result = await api.probeNode(node.id);
                        if (
                            !active.current ||
                            revision !== getSessionRevision()
                        )
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
                        if (
                            !active.current ||
                            revision !== getSessionRevision()
                        )
                            return;
                        if (isSessionProblem(requestError)) {
                            onAccessLost();
                            return;
                        }
                        markProbeFailed(node.id, requestError);
                    }
                }
            }
        } finally {
            if (active.current && revision === getSessionRevision())
                setProbingAll(false);
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
                                disabled={
                                    probingAll ||
                                    activeProbe !== null ||
                                    nodes.length === 0
                                }
                                onClick={() => void probeAll()}
                                size="icon"
                                variant="ghost"
                            >
                                <Gauge
                                    className={
                                        probingAll
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
                                                <p className="truncate text-sm font-medium">
                                                    {node.name}
                                                </p>
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
                                                            disabled={
                                                                probingAll ||
                                                                activeProbe !==
                                                                    null
                                                            }
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

function NodeDetailsPopover({
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

function NodeDetailsView({ details }: { details: NodeDetails }) {
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
