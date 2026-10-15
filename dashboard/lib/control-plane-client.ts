/** AURAGENT Phase 11 Control Plane client. */
export type OrganizationView = {
  organization_id: string;
  name: string;
  status: string;
  created_at: string | null;
  settings_available: boolean;
};

export type ProjectView = {
  project_id: string;
  organization_id: string;
  name: string;
  status: string;
  description: string;
  created_at: string | null;
};

export type ConfigView = {
  organization_id: string;
  version: string;
  values: Record<string, unknown>;
  mutable_keys: string[];
};

export type APIKeyView = {
  key_id: string;
  organization_id: string;
  prefix: string;
  active: boolean;
  created_at: string | null;
  expires_at: string | null;
  last_used_at: string | null;
};

export type UsageSummary = {
  organization_id: string;
  since: string | null;
  request_count: number;
  blocked_count: number;
  approved_count: number;
  denied_count: number;
  estimated_usage_units: number;
};

type Fetcher = typeof fetch;

export function createControlPlaneClient(
  baseUrl = "",
  fetcher: Fetcher = fetch,
) {
  const base = baseUrl.replace(/\/$/, "");

  async function request<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await fetcher(`${base}${path}`, {
      ...init,
      headers: {
        Accept: "application/json",
        ...(init?.headers ?? {}),
      },
    });
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error(`Control Plane API ${response.status}: ${body}`);
    }
    return (await response.json()) as T;
  }

  return {
    organization: () => request<OrganizationView>("/v1/control-plane/organization"),
    projects: () => request<ProjectView[]>("/v1/control-plane/projects"),
    createProject: (name: string, description = "") =>
      request<ProjectView>("/v1/control-plane/projects", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, description }),
      }),
    deleteProject: (name: string) =>
      request<void>(`/v1/control-plane/projects/${encodeURIComponent(name)}`, {
        method: "DELETE",
      }),
    configuration: () => request<ConfigView>("/v1/control-plane/configuration"),
    updateConfiguration: (values: Record<string, unknown>) =>
      request<ConfigView>("/v1/control-plane/configuration", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ values }),
      }),
    apiKeys: () => request<APIKeyView[]>("/v1/control-plane/api-keys"),
    usage: (since?: string, limit = 1000) => {
      const params = new URLSearchParams({ limit: String(limit) });
      if (since) params.set("since", since);
      return request<UsageSummary>(`/v1/control-plane/usage?${params.toString()}`);
    },
  };
}
