import type { ReactNode } from "react";
import { Card } from "@/components/ui/card";

export function AuthCardShell({ children }: { children: ReactNode }) {
    return (
        <main className="flex min-h-screen items-center justify-center bg-background px-4 py-10 text-foreground">
            <div className="boot w-full max-w-md">
                <p className="glow mb-5 px-1 font-sans text-lg font-bold uppercase tracking-[0.34em] text-primary">
                    Chinadapter
                </p>
                <Card className="panel w-full">{children}</Card>
            </div>
        </main>
    );
}
