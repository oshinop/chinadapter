export function formatTime(value?: string): string {
    if (!value) return "—";
    const time = new Date(value);
    return Number.isNaN(time.getTime())
        ? "—"
        : time.toLocaleString(undefined, {
              dateStyle: "medium",
              timeStyle: "short",
          });
}

export function formatCompactTime(value?: string): string {
    if (!value) return "—";
    const time = new Date(value);
    if (Number.isNaN(time.getTime())) return "—";
    const formatted = time.toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "numeric",
        minute: "2-digit",
    });
    return formatted
        .replace(/,\s*/u, " · ")
        .replace(/\s+(AM|PM)$/u, "\u00a0$1");
}
