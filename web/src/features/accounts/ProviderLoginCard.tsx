import type { StatusResponse } from "@/types";
import { AuthCardShell } from "@/components/AuthCardShell";
import { CardContent, CardHeader } from "@/components/ui/card";
import { ProviderCredentialsForm } from "./ProviderCredentialsForm";

export function ProviderLoginCard({
    onSubmit,
    error,
    providers,
    providerAuth,
}: {
    onSubmit: (
        provider: string,
        fields: Record<string, string>,
    ) => Promise<void>;
    error: string;
    providers: string[];
    providerAuth: StatusResponse["providerAuth"];
}) {
    return (
        <AuthCardShell>
            <CardHeader>
                <h1 className="font-sans text-xl font-semibold uppercase tracking-[0.05em]">
                    Add a provider
                </h1>
            </CardHeader>
            <CardContent>
                <ProviderCredentialsForm
                    error={error}
                    idPrefix="initial"
                    onSubmit={onSubmit}
                    providers={providers}
                    providerAuth={providerAuth}
                />
            </CardContent>
        </AuthCardShell>
    );
}
