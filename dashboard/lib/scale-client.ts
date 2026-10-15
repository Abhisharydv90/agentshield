/**
 * AURAGENT Phase 13 Scale client.
 *
 * Scale metadata is operational information. The browser never receives a
 * worker lease token or any authority-bearing scheduler credential.
 */

export type ShardDescriptor = {
  shard_id: number;
  total_shards: number;
  tenant_bucket: number;
  strategy: string;
};

export type RegionDescriptor = {
  region: string;
  control_plane_region: boolean;
  active: boolean;
  priority: number;
  endpoint: string | null;
};

export type HealthSnapshot = {
  status: "healthy" | "degraded" | "unavailable";
  region: string;
  worker_id: string;
  active_leases: number;
  queue_depth: number;
  event_lag: number;
  timestamp: string;
  details: Record<string, unknown>;
};

export function createScaleClient(
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
      throw new Error(`Scale API ${response.status}: ${detail}`);
    }

    return (await response.json()) as T;
  }

  return {
    shard(tenantId: string) {
      return request<ShardDescriptor>(
        `/v1/scale/shard/${encodeURIComponent(tenantId)}`,
      );
    },

    selectRegion(
      regions: RegionDescriptor[],
      preferred?: string,
    ) {
      const query = preferred
        ? `?preferred=${encodeURIComponent(preferred)}`
        : "";
      return request<RegionDescriptor>("/v1/scale/region/select" + query, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ regions }),
      });
    },

    health(input: {
      region: string;
      worker_id: string;
      active_leases: number;
      queue_depth: number;
      event_lag: number;
    }) {
      return request<HealthSnapshot>("/v1/scale/health", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(input),
      });
    },
  };
}
