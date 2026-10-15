/**
 * AURAGENT Phase 12 Ecosystem client.
 *
 * Registry discovery is informational. Registration and disable are
 * authenticated admin actions on the server.
 */

export type EcosystemKind =
  | "plugin"
  | "mcp"
  | "a2a"
  | "sdk"
  | "integration";

export type RegistryEntry = {
  entry_id: string;
  kind: EcosystemKind;
  name: string;
  version: string;
  publisher: string;
  description: string;
  digest_sha256: string;
  verified: boolean;
  enabled: boolean;
  registered_at: string;
  metadata: Record<string, unknown>;
};

export type EcosystemManifest = {
  manifest_version: string;
  ecosystem: "auragent";
  publisher: string;
  name: string;
  version: string;
  kind: EcosystemKind;
  description?: string;
  homepage?: string;
  repository?: string;
  permissions?: string[];
  requested_capabilities?: string[];
  endpoints?: string[];
  metadata?: Record<string, unknown>;
  content_sha256: string;
};

export function createEcosystemClient(
  baseUrl = "",
  fetcher: typeof fetch = fetch,
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
      const detail = await response.text().catch(() => "");
      throw new Error(`Ecosystem API ${response.status}: ${detail}`);
    }

    return (await response.json()) as T;
  }

  return {
    discover(kind?: EcosystemKind, limit = 100) {
      const params = new URLSearchParams({ limit: String(limit) });
      if (kind) params.set("kind", kind);
      return request<RegistryEntry[]>(
        `/v1/ecosystem/discover?${params.toString()}`,
      );
    },

    register(manifest: EcosystemManifest) {
      return request<RegistryEntry>("/v1/ecosystem/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ manifest }),
      });
    },

    disable(entryId: string) {
      return request<{ entry_id: string; status: string }>(
        `/v1/ecosystem/disable/${encodeURIComponent(entryId)}`,
        { method: "POST" },
      );
    },

    exampleManifest() {
      return request<Record<string, unknown>>(
        "/v1/ecosystem/manifest/example",
      );
    },
  };
}
