/**
 * AURAGENT Phase 15 Research client.
 *
 * Results are research/security artifacts. No endpoint here returns an
 * executable containment command or authority-granting credential.
 */

export type AuthorityVector = {
  capabilities: string[];
  operations: string[];
  resources: string[];
  data_scopes: string[];
  network_scopes: string[];
  delegation_depth: number;
  risk_ceiling: number;
};

export type ResearchEvaluation = {
  tenant_id: string;
  trace_id: string;
  subject_id: string;
  authority_conserved: boolean;
  provenance_satisfied: boolean;
  policy_valid: boolean;
  containment: {
    plan_id: string;
    tenant_id: string;
    trace_id: string;
    actions: Array<{
      mode: string;
      subject_id: string;
      reason: string;
      requires_human_approval: boolean;
      reversible: boolean;
      evidence_required: boolean;
    }>;
    trigger: string;
    autonomous_execution_allowed: false;
    created_at: string;
    plan_hash: string;
  } | null;
  decision_proof: {
    proof_id: string;
    decision: string;
    reason: string;
    proof_hash: string;
    executable: false;
  };
  research_invariant: string;
};

export function createResearchClient(
  baseUrl = "",
  fetcher: typeof fetch = fetch,
) {
  const base = baseUrl.replace(/\/$/, "");

  async function request<T>(
    path: string,
    init?: RequestInit,
  ): Promise<T> {
    const response = await fetcher(`${base}${path}`, {
      ...init,
      headers: {
        Accept: "application/json",
        ...(init?.headers ?? {}),
      },
    });

    if (!response.ok) {
      const detail = await response.text().catch(() => "");
      throw new Error(`Research API ${response.status}: ${detail}`);
    }

    return (await response.json()) as T;
  }

  return {
    evaluate(payload: unknown) {
      return request<ResearchEvaluation>("/v1/research/evaluate", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(payload),
      });
    },

    verifyPolicy(policy: unknown) {
      return request<Record<string, unknown>>(
        "/v1/research/verify-policy",
        {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({policy}),
        },
      );
    },

    invariants() {
      return request<Record<string, unknown>>(
        "/v1/research/invariants",
      );
    },
  };
}
