import type { Dispatch, RefObject, SetStateAction } from "react";
import type { ApiClient } from "@/api";
import type { StatusResponse } from "@/types";
import { replaceRoute } from "@/features/access/session";
import { describeError, isSessionProblem } from "@/lib/errors";
import { groupNameCollator } from "@/lib/groups";

export function useProviderActions({
    api,
    loadAuthenticatedData,
    loseAccessSession,
    sessionRevision,
    setLoadError,
    setRefreshing,
    status,
}: {
    api: ApiClient;
    loadAuthenticatedData: () => Promise<StatusResponse | null>;
    loseAccessSession: () => void;
    sessionRevision: RefObject<number>;
    setLoadError: Dispatch<SetStateAction<string>>;
    setRefreshing: Dispatch<SetStateAction<boolean>>;
    status: StatusResponse | null;
}) {
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

    return { loginAccount, refreshProvider, removeProvider, signOutAll, refreshAll };
}
