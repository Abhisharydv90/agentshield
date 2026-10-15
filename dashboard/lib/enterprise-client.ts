/**
 * AURAGENT Phase 14 Enterprise client.
 *
 * Enterprise APIs expose policy metadata and key descriptors, never raw
 * cryptographic material or credentials.
 */

export type EnterprisePolicy = {
  organization_id: string;
  enforce_sso: boolean;
  deny_public_integrations: boolean;
  require_human_approval_for_high_risk: boolean;
  max_session_minutes: number;
  allowed_regions: string[];
  denied_regions: string[];
  minimum_tls_version: string;
  require_evidence_for_actions: boolean;
  require_signed_ecosystem_manifests: boolean;
  version: number;
};

export type RetentionPolicy = {
  organization_id: string;
  evidence_days: number;
  audit_days: number;
  security_event_days: number;
  memory_days: number;
  legal_hold: boolean;
  version: number;
};

export type KeyDescriptor = {
  key_id: string;
  organization_id: string;
  purpose: string;
  algorithm: string;
  version: number;
  active: boolean;
  created_at: string;
  expires_at: string | null;
  external_key_reference: string | null;
  public_material_fingerprint: string | null;
};

export type CompliancePackageManifest = {
  organization_id: string;
  framework: string;
  generated_at: string;
  control_count: number;
  satisfied_count: number;
  evidence_count: number;
  package_sha256: string;
};

export type TenantSecurityPosture = {
  organization_id: string;
  sso_enabled: boolean;
  enforce_sso: boolean;
  evidence_retention_days: number;
  audit_retention_days: number;
  siem_enabled: boolean;
  active_signing_keys: number;
  active_encryption_keys: number;
  legal_hold: boolean;
  generated_at: string;
};

export function createEnterpriseClient(
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
      throw new Error(`Enterprise API ${response.status}: ${detail}`);
    }

    return (await response.json()) as T;
  }

  return {
    validateSSO(config: unknown) {
      return request<Record<string, unknown>>(
        "/v1/enterprise/sso/validate",
        {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({config}),
        },
      );
    },

    validateRetention(policy: RetentionPolicy) {
      return request<Record<string, unknown>>(
        "/v1/enterprise/retention/validate",
        {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({policy}),
        },
      );
    },

    validateSIEM(destination: unknown) {
      return request<Record<string, unknown>>(
        "/v1/enterprise/siem/validate",
        {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({destination}),
        },
      );
    },

    checkRegion(policy: EnterprisePolicy, region: string) {
      return request<Record<string, unknown>>(
        `/v1/enterprise/policy/region?region=${encodeURIComponent(region)}`,
        {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({policy, region}),
        },
      );
    },

    provisionKey(purpose = "signing") {
      return request<KeyDescriptor>(
        `/v1/enterprise/keys/provision?purpose=${encodeURIComponent(purpose)}`,
        {method: "POST"},
      );
    },

    keyDigest() {
      return request<{organization_id: string; inventory_sha256: string}>(
        "/v1/enterprise/keys/digest",
      );
    },

    compliancePackage(framework = "soc2", evidenceCount = 0) {
      return request<CompliancePackageManifest>(
        `/v1/enterprise/compliance/package?framework=${encodeURIComponent(framework)}&evidence_count=${evidenceCount}`,
        {method: "POST"},
      );
    },

    posture(
      policy: EnterprisePolicy,
      retention: RetentionPolicy,
      ssoEnabled = false,
      siemEnabled = false,
    ) {
      const params = new URLSearchParams({
        sso_enabled: String(ssoEnabled),
        siem_enabled: String(siemEnabled),
      });
      return request<TenantSecurityPosture>(
        `/v1/enterprise/posture?${params.toString()}`,
        {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({policy, retention}),
        },
      );
    },
  };
}
