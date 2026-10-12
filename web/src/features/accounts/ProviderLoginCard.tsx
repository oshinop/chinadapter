import { AuthCardShell } from "@/components/AuthCardShell";
import { CardContent, CardDescription, CardHeader } from "@/components/ui/card";
import { ProviderCredentialsForm } from "./ProviderCredentialsForm";

export function ProviderLoginCard({
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
