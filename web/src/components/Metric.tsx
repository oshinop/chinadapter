export function Metric({
    label,
    title,
    value,
}: {
    label: string;
    title?: string;
    value: string;
}) {
    return (
        <div className="min-w-0 border-l border-primary/40 pl-3">
            <p className="text-[0.65rem] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
                {label}
            </p>
            <p
                className="mt-1.5 break-words font-sans text-2xl font-semibold leading-tight tabular-nums"
                title={title}
            >
                {value}
            </p>
        </div>
    );
}
