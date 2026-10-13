import { useState } from "react";
import type { FormEvent } from "react";
import { LoaderCircle } from "lucide-react";
import { Field, FormError, selectClassName } from "@/components/forms";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { describeError } from "@/lib/errors";
import { providerLabel } from "./providers";

export function ProviderCredentialsForm({
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
            setLocalError("Enter your email or phone number and password.");
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
            <Field label="Email or phone" name={accountID}>
                <Input
                    autoComplete="off"
                    id={accountID}
                    inputMode="email"
                    name="account"
                    onChange={(event) => setAccount(event.currentTarget.value)}
                    type="text"
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
