export type Route = "/" | "/signin";
export type SessionState = "checking" | "setup" | "access_login" | "available";

export function routeFromLocation(): Route {
    return window.location.pathname === "/signin" ? "/signin" : "/";
}

export function replaceRoute(route: Route): void {
    if (window.location.pathname !== route)
        window.history.replaceState(null, "", route);
    window.dispatchEvent(new PopStateEvent("popstate"));
}
