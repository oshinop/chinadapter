import { ApiError } from "@/api";

export function isSessionProblem(error: unknown): boolean {
    return (
        error instanceof ApiError &&
        (error.problem.status === 401 || error.problem.status === 403)
    );
}

export function describeError(error: unknown): string {
    if (error instanceof ApiError) {
        if (error.problem.code === "rate_limited")
            return "Too many attempts. Wait a moment and try again.";
        if (error.problem.code === "invalid_access_token")
            return "That access token was not accepted.";
        if (error.problem.code === "invalid_next_access_token")
            return "Use a different access token of 16–128 bytes.";
        if (error.problem.code === "login_rejected")
            return "The provider rejected that email or password.";
        return error.problem.detail || error.problem.title;
    }
    return "The local service did not complete that request.";
}
