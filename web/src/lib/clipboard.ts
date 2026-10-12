export async function copyText(value: string): Promise<boolean> {
    try {
        if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(value);
            return true;
        }
    } catch {
        // Fall through to the legacy copy command for non-secure LAN origins.
    }

    const textArea = document.createElement("textarea");
    textArea.value = value;
    textArea.setAttribute("readonly", "");
    textArea.style.position = "fixed";
    textArea.style.opacity = "0";
    textArea.style.pointerEvents = "none";
    document.body.append(textArea);
    textArea.select();
    try {
        return document.execCommand("copy");
    } catch {
        return false;
    } finally {
        textArea.remove();
    }
}
