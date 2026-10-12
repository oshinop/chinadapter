import type { ReactNode } from "react";
import { Card, CardFooter } from "@/components/ui/card";

export function AuthCardShell({ children }: { children: ReactNode }) {
    return (
        <main className="flex min-h-screen items-center justify-center bg-background px-4 py-10 text-foreground">
            <div className="boot w-full max-w-md">
                <div className="mb-5 flex items-end justify-between gap-4 px-1">
                    <div>
                        <p className="glow font-sans text-lg font-bold uppercase tracking-[0.34em] text-primary">
                            Chinadapter
                        </p>
                        <p className="mt-1 text-[0.625rem] uppercase tracking-[0.24em] text-muted-foreground">
                            Local control plane
                        </p>
                    </div>
                    <div
                        aria-hidden="true"
                        className="mb-1.5 flex items-center gap-1.5"
                    >
                        <span className="led led--ok" />
                        <span className="led led--warn led--pulse" />
                        <span className="led" />
                    </div>
                </div>
                <Card className="panel w-full">
                    {children}
                    <CardFooter className="justify-between border-t border-dashed border-border/70 pt-4 text-[0.625rem] uppercase tracking-[0.22em] text-muted-foreground [&.border-t]:pt-4">
                        <span>Console access</span>
                        <span aria-hidden="true">▪ ▪ ▪</span>
                    </CardFooter>
                </Card>
            </div>
        </main>
    );
}
