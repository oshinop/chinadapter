import type { ServiceState } from "@/types";

export const providerLoginStates: Partial<Record<ServiceState, true>> = {
    signed_out: true,
    expired: true,
};

const providerLabels: Record<string, string> = {
    kuaifan: "KuaiFan",
    quickfox: "QuickFox",
    transocks: "Transocks",
};

export function providerLabel(provider: string): string {
    return providerLabels[provider] ?? provider;
}
