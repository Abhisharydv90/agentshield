export type EvidenceNode = {
  evidence_id: string;
  tenant_id: string;
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
  tenant_id: string;
  trace_id: string;
  from_evidence_id: string;
  to_evidence_id: string;
  relation: string;
  created_at: string;
};

export type EvidencePage = {
  nodes: EvidenceNode[];
  next_cursor: string | null;
  has_more: boolean;
};

export type EvidenceGraph = {
  root_evidence_id: string;
  nodes: EvidenceNode[];
  edges: EvidenceEdge[];
  truncated: boolean;
};

export type EvidenceIssue = {
  code: string;
  detail: string;
};

export type EvidenceVerification = {
  valid: boolean;
  chain_valid: boolean;
  chain_length: number;
  broken_at: string | null;
  nodes_checked: number;
  edges_checked: number;
  truncated: boolean;
  issues: EvidenceIssue[];
  verified_at: string;
};

export type EvidenceSummary = {
  tenant: string;
  node_count: number;
  edge_count: number;
};

export type EvidenceTraceRecord = {
  sequence: number;
  event_id: string;
  evidence_id: string | null;
  timestamp: string;
  request_id: string | null;
  threat_category: string;
  action_taken: string;
  record_hash: string;
  prev_hash: string | null;
  artifact_hash: string | null;
  node_type: string | null;
  source: string | null;
  metadata_redacted: Record<string, unknown>;
  record_hash_valid: boolean;
  evidence_hash_valid: boolean;
  predecessor_evidence_id: string | null;
  predecessor_relation: string | null;
};

export type EvidenceTrace = {
  trace_id: string;
  event_count: number;
  node_count: number;
  edge_count: number;
  start_time: string | null;
  end_time: string | null;
  truncated: boolean;
  integrity: {
    status: "verified" | "partial" | "invalid" | string;
    events_checked: number;
    evidence_checked: number;
    missing_evidence: number;
  };
  records: EvidenceTraceRecord[];
};

export type EvidenceReplay = {
  trace_id: string;
  mode: "forensic" | string;
  executed: false;
  mutations_performed: false;
  generated_at: string;
  truncated: boolean;
  records: EvidenceTraceRecord[];
};

export type EvidenceExport = {
  schema_version: string;
  package_hash: string;
  exported_at: string;
  tenant: string;
  truncated: boolean;
  verification: EvidenceVerification;
  nodes: EvidenceNode[];
  edges: EvidenceEdge[];
  privacy: Record<string, string>;
};

export type EvidenceComplianceReport = {
  schema_version: string;
  report_id: string;
  generated_at: string;
  tenant: string;
  package_hash: string;
  node_count: number;
  edge_count: number;
  truncated: boolean;
  verification: EvidenceVerification;
  controls: Record<string, string>;
};

function buildUrl(
  path: string,
  params: Record<
    string,
    string | number | null | undefined
  > = {}
): string {
  const search = new URLSearchParams();

  for (const [key, value] of Object.entries(params)) {
    if (
      value !== undefined &&
      value !== null &&
      value !== ""
    ) {
      search.set(key, String(value));
    }
  }

  const query = search.toString();

  return query
    ? `${path}?${query}`
    : path;
}

async function request<T>(
  path: string,
  init: RequestInit = {}
): Promise<T> {
  const response = await fetch(path, {
    ...init,
    credentials: "include",
    cache: "no-store",
    headers: {
      Accept: "application/json",
      ...(init.headers ?? {}),
    },
  });

  const text = await response.text();

  let payload: unknown = null;

  try {
    payload = text
      ? JSON.parse(text)
      : null;
  } catch {
    payload = text;
  }

  if (!response.ok) {
    const detail =
      typeof payload === "object" &&
      payload !== null &&
      "error" in payload
        ? String(
            (
              payload as {
                error?: unknown;
              }
            ).error
          )
        : `HTTP ${response.status}`;

    throw new Error(detail);
  }

  return payload as T;
}

export async function fetchEvidencePage(
  params: {
    traceId?: string;
    nodeType?: string;
    source?: string;
    artifactHash?: string;
    securityEventId?: string;
    pageSize?: number;
    cursor?: string;
  } = {}
): Promise<EvidencePage> {
  return request<EvidencePage>(
    buildUrl("/api/evidence/nodes", {
      trace_id:
        params.traceId,
      node_type:
        params.nodeType,
      source:
        params.source,
      artifact_hash:
        params.artifactHash,
      security_event_id:
        params.securityEventId,
      page_size:
        params.pageSize ?? 50,
      cursor:
        params.cursor,
    })
  );
}

export async function fetchEvidenceNode(
  evidenceId: string
): Promise<EvidenceNode> {
  return request<EvidenceNode>(
    `/api/evidence/nodes/${encodeURIComponent(
      evidenceId
    )}`
  );
}

export async function fetchEvidenceGraph(
  evidenceId: string,
  depth = 2,
  limit = 100
): Promise<EvidenceGraph> {
  return request<EvidenceGraph>(
    buildUrl(
      `/api/evidence/graph/${encodeURIComponent(
        evidenceId
      )}`,
      {
        depth,
        limit,
      }
    )
  );
}

export async function fetchEvidenceTrace(
  traceId: string,
  limit = 250
): Promise<EvidenceTrace> {
  return request<EvidenceTrace>(
    buildUrl(
      `/api/evidence/trace/${encodeURIComponent(
        traceId
      )}`,
      {
        limit,
      }
    )
  );
}

export async function fetchEvidenceReplay(
  traceId: string,
  limit = 250
): Promise<EvidenceReplay> {
  return request<EvidenceReplay>(
    buildUrl(
      `/api/evidence/replay/${encodeURIComponent(
        traceId
      )}`,
      {
        limit,
      }
    )
  );
}

export async function verifyEvidence(): Promise<EvidenceVerification> {
  return request<EvidenceVerification>(
    "/api/evidence/verify"
  );
}

export async function fetchEvidenceSummary(): Promise<EvidenceSummary> {
  return request<EvidenceSummary>(
    "/api/evidence/summary"
  );
}

export async function fetchEvidenceComplianceReport(
  maxNodes = 1000
): Promise<EvidenceComplianceReport> {
  return request<EvidenceComplianceReport>(
    buildUrl(
      "/api/evidence/compliance/report",
      {
        max_nodes: maxNodes,
      }
    )
  );
}

export async function exportEvidence(
  maxNodes = 1000
): Promise<Blob> {
  const response = await fetch(
    buildUrl(
      "/api/evidence/export",
      {
        max_nodes: maxNodes,
      }
    ),
    {
      credentials: "include",
      cache: "no-store",
      headers: {
        Accept:
          "application/json",
      },
    }
  );

  if (!response.ok) {
    const text =
      await response.text();

    throw new Error(
      text ||
        `HTTP ${response.status}`
    );
  }

  return response.blob();
}