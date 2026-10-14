import { LoaderCircle } from "lucide-react";
import { AuthCardShell } from "@/components/AuthCardShell";
import { CardHeader } from "@/components/ui/card";

export function LoadingCard() {
    return (
        <AuthCardShell>
            <CardHeader>
                <h1 className="flex items-center gap-2.5 font-sans text-lg font-semibold uppercase tracking-[0.05em]">
                    <LoaderCircle className="size-5 animate-spin text-primary" />
                    Checking access
                </h1>
            </CardHeader>
        </AuthCardShell>
    );
}
