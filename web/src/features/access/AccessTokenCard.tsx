import { useState } from "react";
import type { FormEvent } from "react";
import { LoaderCircle } from "lucide-react";
import { AuthCardShell } from "@/components/AuthCardShell";
import { Field, FormError } from "@/components/forms";
import { Button } from "@/components/ui/button";
import { CardContent, CardDescription, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { describeError } from "@/lib/errors";

export function AccessTokenCard({
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
