/**
 * AURAGENT Phase 10 Investigation API client.
 *
 * The client exposes only read-only investigation surfaces.
 * Replay is forensic reconstruction and is never an execution API.
 */

export type EvidenceNode = {
  evidence_id: string;
  trace_id: string;
  node_type: string;
  schema_version: string;
  artifact_hash: string;
  source: string;
  metadata_redacted: Record<string, unknown>;
  security_event_id: string | null;
  created_at: string;
};

export type EvidenceEdge = {
  edge_id: string;
  trace_id: string;
  from_evidence_id: string;
  to_evidence_id: string;
  relation: string;
  created_at: string;
};

export type GraphView = {
  root_evidence_id: string;
  nodes: EvidenceNode[];
  edges: EvidenceEdge[];
  depth: number;
  truncated: boolean;
};

export type TimelineItem = {
  sequence: number;
  timestamp: string;
  evidence_id: string;
  node_type: string;
  source: string;
  action: string | null;
  threat_category: string | null;
  request_id: string | null;
};

export type CauseCandidate = {
  evidence_id: string;
  node_type: string;
  relation: string | null;
  distance: number;
  score: number;
  explanation: string;
};

export type ReplayStep = {
  sequence: number;
  timestamp: string;
  evidence_id: string;
  event_type: string;
  description: string;
  authority_context: string;
  executable: false;
};

export type ExplainabilityView = {
  subject_evidence_id: string;
  summary: string;
  chain: string[];
  influence_sources: string[];
  authority_statement: string;
  evidence_statement: string;
};

export type IncidentView = {
  incident_id: string;
  tenant_id: string;
  trace_id: string;
  status: string;
  first_seen: string | null;
  last_seen: string | null;
  node_count: number;
  edge_count: number;
  event_count: number;
  root_evidence_id: string | null;
  timeline: TimelineItem[];
  causes: CauseCandidate[];
  graph: GraphView | null;
  explainability: ExplainabilityView | null;
  forensic_replay: ReplayStep[];
  bounded: boolean;
  replay_is_executable: false;
};

export type SearchHit = {
  evidence_id: string;
  trace_id: string;
  node_type: string;
  source: string;
  artifact_hash: string;
  created_at: string;
  matched_fields: string[];
};

export type InvestigationClientOptions = {
  baseUrl?: string;
  fetcher?: typeof fetch;
};

export function createInvestigationClient(
  options: InvestigationClientOptions = {},
) {
  const baseUrl = (options.baseUrl ?? "").replace(/\/$/, "");
  const fetcher = options.fetcher ?? fetch;

  async function request<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await fetcher(`${baseUrl}${path}`, {
      ...init,
      headers: {
        Accept: "application/json",
        ...(init?.headers ?? {}),
      },
    });

    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error(`Investigation API ${response.status}: ${body}`);
    }

    return (await response.json()) as T;
  }

  return {
    incident(traceId: string, params: Record<string, string | number> = {}) {
      return request<IncidentView>(
        `/v1/investigation/incident/${encodeURIComponent(traceId)}?${new URLSearchParams(
          Object.entries(params).map(([key, value]) => [key, String(value)]),
        )}`,
      );
    },

    graph(evidenceId: string, params: Record<string, string | number> = {}) {
      return request<GraphView>(
        `/v1/investigation/graph/${encodeURIComponent(evidenceId)}?${new URLSearchParams(
          Object.entries(params).map(([key, value]) => [key, String(value)]),
        )}`,
      );
    },

    timeline(traceId: string, params: Record<string, string | number> = {}) {
      return request<TimelineItem[]>(
        `/v1/investigation/timeline/${encodeURIComponent(traceId)}?${new URLSearchParams(
          Object.entries(params).map(([key, value]) => [key, String(value)]),
        )}`,
      );
    },

    causes(traceId: string, params: Record<string, string | number> = {}) {
      return request<CauseCandidate[]>(
        `/v1/investigation/causes/${encodeURIComponent(traceId)}?${new URLSearchParams(
          Object.entries(params).map(([key, value]) => [key, String(value)]),
        )}`,
      );
    },

    replay(traceId: string, params: Record<string, string | number> = {}) {
      return request<ReplayStep[]>(
        `/v1/investigation/replay/${encodeURIComponent(traceId)}?${new URLSearchParams(
          Object.entries(params).map(([key, value]) => [key, String(value)]),
        )}`,
      );
    },

    explain(evidenceId: string, params: Record<string, string | number> = {}) {
      return request<ExplainabilityView>(
        `/v1/investigation/explain/${encodeURIComponent(evidenceId)}?${new URLSearchParams(
          Object.entries(params).map(([key, value]) => [key, String(value)]),
        )}`,
      );
    },

    search(query: string, params: Record<string, string | number | undefined> = {}) {
      const all = { q: query, ...params };
      const cleaned = Object.entries(all).filter(([, value]) => value !== undefined);
      return request<SearchHit[]>(
        `/v1/investigation/search?${new URLSearchParams(
          cleaned.map(([key, value]) => [key, String(value)]),
        )}`,
      );
    },
  };
}
