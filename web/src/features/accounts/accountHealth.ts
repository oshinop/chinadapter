import type { AccountSummary } from "@/types";
import { formatCompactTime } from "@/lib/time";

export type LampTone = "ok" | "warn" | "err" | "off";

export const lampClass: Record<LampTone, string> = {
    ok: "led--ok",
    warn: "led--warn",
    err: "led--err",
    off: "",
};

export interface AccountIssue {
    tone: "warn" | "err";
    /** Short cause, e.g. "Can't reach provider". */
    summary: string;
    /** What happens next or what the operator should do. */
    action: string;
}

const causes: Record<string, string> = {
    network: "Can't reach provider",
    session_rejected: "Provider ended the session",
    login_rejected: "Provider rejected the saved sign-in",
    device_limit: "Too many devices signed in",
    authority_expired: "Session expired",
    no_session: "No saved session to renew",
};

export function accountIssue(account?: AccountSummary): AccountIssue | null {
    if (!account) return null;
    const cause = causes[account.refreshProblem ?? ""] ?? "Refresh failed";
    switch (account.refreshStatus) {
        case "needs_relogin":
            return {
                tone: "err",
                summary: cause,
                action: "Automatic refresh paused. Refresh to retry, or remove and add it again.",
            };
        case "refresh_failing":
            return {
                tone: "warn",
                summary: cause,
                action: account.nextRefreshAt
                    ? `Retrying ${formatCompactTime(account.nextRefreshAt)}.`
                    : "Retrying automatically.",
            };
        default:
            return null;
    }
}

export function accountTone(account?: AccountSummary): LampTone {
    if (!account) return "off";
    return accountIssue(account)?.tone ?? "ok";
}
