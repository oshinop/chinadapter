import { useCallback, useEffect, useRef, useState } from "react";
import { ApiClient } from "@/api";
import type { NodeRecord, StatusResponse } from "@/types";
import { providerLoginStates } from "@/features/accounts/providers";
import { useProviderActions } from "@/features/accounts/useProviderActions";
import { useConsoleEvents } from "@/features/events/useConsoleEvents";
import { describeError, isSessionProblem } from "@/lib/errors";
import { replaceRoute, routeFromLocation } from "./session";
import type { Route, SessionState } from "./session";

export function useConsoleSession(providedApi?: ApiClient) {
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

    useConsoleEvents({ api, queueAuthenticatedReload, session, setNodes });

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

    const getSessionRevision = useCallback(() => sessionRevision.current, []);
    const providerActions = useProviderActions({
        api,
        loadAuthenticatedData,
        loseAccessSession,
        sessionRevision,
        setLoadError,
        setRefreshing,
        status,
    });

    return {
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
        loseAccessSession,
        lockConsole,
        getSessionRevision,
        setNodes,
        ...providerActions,
    };
}
