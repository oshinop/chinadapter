import { formatTime } from "@/lib/time";

interface SubscriptionValidity {
    summary: string;
    endsAt?: string;
}

function describeSubscriptionValidity(
    subscriptionActive: boolean,
    subscriptionEndsAt?: string,
) {
    if (!subscriptionActive) return { summary: "Free" };
    if (!subscriptionEndsAt)
        return { summary: "Active · End date unavailable" };

    const endTime = new Date(subscriptionEndsAt);
    if (Number.isNaN(endTime.getTime()))
        return { summary: "Active · End date unavailable" };

    const remaining = endTime.getTime() - Date.now();
    const endsAt = formatTime(subscriptionEndsAt);
    if (remaining <= 0) return { summary: "Expired", endsAt };
    if (remaining < 60 * 60 * 1000)
        return { summary: "Active · Valid for less than an hour", endsAt };

    const hours = Math.ceil(remaining / (60 * 60 * 1000));
    if (hours < 24)
        return {
            summary: `Active · Valid for ${hours} ${hours === 1 ? "hour" : "hours"}`,
            endsAt,
        };

    const days = Math.ceil(remaining / (24 * 60 * 60 * 1000));
    return {
        summary: `Active · Valid for ${days} ${days === 1 ? "day" : "days"}`,
        endsAt,
    };
}

export function SubscriptionMetric({
    subscriptionActive,
    subscriptionEndsAt,
}: {
    subscriptionActive: boolean;
    subscriptionEndsAt?: string;
}) {
    const validity = describeSubscriptionValidity(
        subscriptionActive,
        subscriptionEndsAt,
    );
    return (
        <div className="border-l border-primary/40 pl-3">
            <p className="text-[0.65rem] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
                Subscription
            </p>
            <p className="mt-1.5 break-words font-sans text-lg font-semibold leading-tight tabular-nums">
                {validity.summary}
            </p>
            {validity.endsAt ? (
                <p
                    className="mt-1 text-xs text-muted-foreground"
                    title={validity.endsAt}
                >
                    Ends {validity.endsAt}
                </p>
            ) : null}
        </div>
    );
}
