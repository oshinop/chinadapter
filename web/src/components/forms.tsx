import type { ReactNode } from "react";

export const selectClassName =
    "flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm shadow-xs outline-none transition-[color,box-shadow] focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50";

export function Field({
    label,
    name,
    children,
}: {
    label: string;
    name: string;
    children: ReactNode;
}) {
    return (
        <label className="grid gap-2" htmlFor={name}>
            <span className="text-[0.65rem] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
                {label}
            </span>
            {children}
        </label>
    );
}

export function FormError({ message }: { message: string }) {
    return message ? (
        <p
            className="flex items-start gap-2.5 rounded-sm border border-destructive/35 bg-destructive/10 px-3 py-2.5 text-[0.8125rem] leading-5 text-destructive"
            role="alert"
        >
            <span
                aria-hidden="true"
                className="led led--err led--pulse mt-1.5"
            />
            <span className="min-w-0">{message}</span>
        </p>
    ) : null;
}
