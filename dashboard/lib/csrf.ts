/**
 * Reads the CSRF cookie and returns its value.
 * The cookie is set by the backend on every /api/* response.
 */
export function getCsrfToken(): string {
  if (typeof document === "undefined") return "";
  const match = document.cookie
    .split("; ")
    .find((row) => row.startsWith("agentshield_csrf="));
  return match ? decodeURIComponent(match.split("=")[1]) : "";
}

/**
 * Wrapper around fetch that automatically:
 *  - sends credentials (cookies)
 *  - sends the CSRF token header on state-changing requests
 */
export async function apiFetch(
  url: string,
  options: RequestInit = {}
): Promise<Response> {
  const method = (options.method ?? "GET").toUpperCase();
  const needsCsrf = !["GET", "HEAD", "OPTIONS"].includes(method);

  const headers = new Headers(options.headers ?? {});
  if (!headers.has("Content-Type") && options.body) {
    headers.set("Content-Type", "application/json");
  }
  if (needsCsrf) {
    headers.set("X-CSRF-Token", getCsrfToken());
  }

  return fetch(url, {
    ...options,
    headers,
    credentials: "include",
  });
}