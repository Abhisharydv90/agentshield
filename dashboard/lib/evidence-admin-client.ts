export type EvidenceAdminStatus = {
  phase: string;
  service: string;
  tenant_id: string;
  evidence_nodes: number;
  evidence_edges: number;
  security_events: number;
  features: {
    immutable_evidence: boolean;
    forensic_replay: boolean;
    distributed_invariants: boolean;
    external_anchor_prepare: boolean;
    raw_evidence_export: boolean;
  };
};

export type EvidenceVerification = {
  tenant_id: string;
  audit_chain: {
    valid: boolean;
    length: number;
    broken_at: string | null;
  };
  evidence: {
    nodes_checked: number;
    edges_checked: number;
    truncated: boolean;
    artifact_hashes_present: boolean;
    status: string;
  };
};

export type CompliancePackage = {
  schema: string;
  tenant_id: string;
  package_hash: string;
  verification: {
    audit_chain: {
      valid: boolean;
      length: number;
      broken_at: string | null;
    };
    evidence_export_truncated: boolean;
  };
  nodes: Array<{
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
  }>;
  edges: Array<{
    edge_id: string;
    tenant_id: string;
    trace_id: string;
    from_evidence_id: string;
    to_evidence_id: string;
    relation: string;
    created_at: string;
  }>;
  truncated: boolean;
};

export type PreparedAnchor = {
  submitted: false;
  reason: string;
  document: {
    scheme: string;
    tenant_id: string;
    package_hash: string;
  };
  document_digest: string;
};

export type EvidenceAdminClientOptions = {
  baseUrl?: string;
  fetcher?: typeof fetch;
};

export class EvidenceAdminClient {
  private readonly baseUrl: string;
  private readonly fetcher: typeof fetch;

  constructor(options: EvidenceAdminClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? "").replace(/\/+$/, "");
    this.fetcher = options.fetcher ?? fetch;
  }

  async status(): Promise<EvidenceAdminStatus> {
    return this.request<EvidenceAdminStatus>("/v1/evidence/admin/status");
  }

  async verify(): Promise<EvidenceVerification> {
    return this.request<EvidenceVerification>("/v1/evidence/admin/verify", {
      method: "POST",
    });
  }

  async trace(traceId: string): Promise<Record<string, unknown>> {
    const encoded = encodeURIComponent(traceId);
    return this.request<Record<string, unknown>>(
      `/v1/evidence/admin/trace/${encoded}`,
    );
  }

  async exportCompliance(): Promise<CompliancePackage> {
    return this.request<CompliancePackage>("/v1/evidence/admin/export");
  }

  async prepareAnchor(packageHash: string, tenantId: string): Promise<PreparedAnchor> {
    return this.request<PreparedAnchor>("/v1/evidence/admin/anchor/prepare", {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        tenant_id: tenantId,
        package_hash: packageHash,
      }),
    });
  }

  private async request<T>(
    path: string,
    init?: RequestInit,
  ): Promise<T> {
    const response = await this.fetcher(`${this.baseUrl}${path}`, {
      credentials: "include",
      ...init,
    });

    if (!response.ok) {
      throw new Error(`evidence_admin_request_failed:${response.status}`);
    }

    return (await response.json()) as T;
  }
}
