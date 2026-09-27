/**
 * Thin wrapper around the auth API. All endpoints are proxied through
 * Next.js rewrites to the FastAPI backend, so we always call relative URLs.
 */

const API = "/api";

export type User = {
  user_id: string;
  tenant_id: string;
  email: string;
  name: string;
  role: string;
  tenant_slug: string;
};

export type SignupResponse = {
  user: User;
  api_key: string;
};

export class ApiError extends Error {
  status: number;
  detail: any;

  constructor(status: number, detail: any) {
    super(typeof detail === "string" ? detail : "API error");
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers ?? {}),
    },
    credentials: "include",
  });

  const text = await res.text();
  let body: any = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }

  if (!res.ok) {
    throw new ApiError(res.status, body?.detail ?? body ?? res.statusText);
  }

  return body as T;
}

export const auth = {
  signup: (data: {
    email: string;
    password: string;
    name: string;
    tenant_name: string;
  }) =>
    request<SignupResponse>("/auth/signup", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  login: (data: { email: string; password: string }) =>
    request<{ user: User }>("/auth/login", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  logout: () =>
    request<{ ok: boolean }>("/auth/logout", { method: "POST" }),

  me: () => request<User>("/auth/me", { method: "GET" }),
};