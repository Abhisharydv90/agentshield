"use client";

import Link from "next/link";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Search,
  ShieldCheck,
} from "lucide-react";
import {
  useEffect,
  useState,
} from "react";
import {
  useSearchParams,
} from "next/navigation";

import {
  EvidenceGraph,
} from "@/components/evidence/evidence-graph";

import {
  type EvidenceGraph as GraphData,
  type EvidenceNode,
  type EvidenceVerification,
  fetchEvidenceGraph,
  fetchEvidenceNode,
  verifyEvidence,
} from "@/lib/evidence-client";

export default function InvestigationPage() {
  const params =
    useSearchParams();

  const initialId =
    params.get("evidence") ?? "";

  const [input, setInput] =
    useState(initialId);

  const [selected, setSelected] =
    useState<EvidenceNode | null>(
      null
    );

  const [graph, setGraph] =
    useState<GraphData | null>(
      null
    );

  const [verification, setVerification] =
    useState<EvidenceVerification | null>(
      null
    );

  const [error, setError] =
    useState<string | null>(null);

  const [loading, setLoading] =
    useState(false);

  useEffect(() => {
    if (initialId) {
      void investigate(initialId);
    }

    // Initial URL-driven investigation only.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialId]);

  async function investigate(
    evidenceId = input
  ) {
    const normalized =
      evidenceId.trim();

    if (!normalized) {
      setError(
        "Enter an evidence ID."
      );
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const [node, graphData] =
        await Promise.all([
          fetchEvidenceNode(
            normalized
          ),
          fetchEvidenceGraph(
            normalized,
            4,
            150
          ),
        ]);

      setSelected(node);
      setGraph(graphData);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Investigation failed"
      );
      setSelected(null);
      setGraph(null);
    } finally {
      setLoading(false);
    }
  }

  async function runVerification() {
    setError(null);

    try {
      const result =
        await verifyEvidence();

      setVerification(result);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Verification failed"
      );
    }
  }

  return (
    <main className="min-h-screen bg-black text-slate-200">
      <div className="border-b border-cyan-500/10 bg-black/80 px-6 py-4">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-4">
          <div>
            <Link
              href="/dashboard/evidence"
              className="mb-2 flex items-center gap-1 text-[9px] font-mono uppercase tracking-[0.18em] text-slate-600 hover:text-cyan-400"
            >
              <ArrowLeft className="h-3 w-3" />
              Evidence control plane
            </Link>

            <div className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-cyan-400" />
              <h1 className="text-sm font-mono tracking-[0.28em] uppercase text-cyan-400">
                Security Investigation
              </h1>
            </div>

            <div className="mt-1 text-[9px] font-mono text-slate-600">
              Bounded causal traversal · tenant-scoped
            </div>
          </div>

          <Link
            href="/dashboard"
            className="border border-emerald-500/15 px-3 py-2 text-[9px] font-mono uppercase tracking-[0.18em] text-slate-500 hover:text-emerald-400"
          >
            Core dashboard
          </Link>
        </div>
      </div>

      <div className="mx-auto max-w-7xl space-y-5 px-6 py-6">
        <div className="grid gap-3 lg:grid-cols-[1fr_auto_auto]">
          <div className="flex items-center gap-2 border border-cyan-500/15 bg-black/50 px-3">
            <Search className="h-3.5 w-3.5 text-slate-600" />

            <input
              value={input}
              onChange={(event) =>
                setInput(
                  event.target.value
                )
              }
              onKeyDown={(event) => {
                if (
                  event.key === "Enter"
                ) {
                  void investigate();
                }
              }}
              placeholder="Evidence UUID"
              className="w-full bg-transparent py-3 text-xs font-mono text-slate-200 outline-none placeholder:text-slate-700"
            />
          </div>

          <button
            onClick={() =>
              void investigate()
            }
            disabled={loading}
            className="border border-cyan-400/30 px-4 py-3 text-[10px] font-mono uppercase tracking-[0.18em] text-cyan-400 hover:bg-cyan-500/5 disabled:opacity-40"
          >
            {loading
              ? "Loading…"
              : "Investigate"}
          </button>

          <button
            onClick={() =>
              void runVerification()
            }
            className="flex items-center justify-center gap-2 border border-emerald-400/20 px-4 py-3 text-[10px] font-mono uppercase tracking-[0.18em] text-emerald-400 hover:bg-emerald-500/5"
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            Verify
          </button>
        </div>

        {error && (
          <div className="flex items-center gap-2 border border-rose-500/20 bg-rose-500/5 px-4 py-3 text-xs font-mono text-rose-300">
            <AlertTriangle className="h-4 w-4" />
            {error}
          </div>
        )}

        {verification && (
          <div
            className={`border px-4 py-4 ${
              verification.valid
                ? "border-emerald-500/20 bg-emerald-500/5"
                : "border-rose-500/20 bg-rose-500/5"
            }`}
          >
            <div className="flex items-center gap-3">
              {verification.valid ? (
                <CheckCircle2 className="h-5 w-5 text-emerald-400" />
              ) : (
                <AlertTriangle className="h-5 w-5 text-rose-400" />
              )}

              <div>
                <div
                  className={`text-xs font-mono font-bold uppercase tracking-[0.18em] ${
                    verification.valid
                      ? "text-emerald-400"
                      : "text-rose-400"
                  }`}
                >
                  {verification.valid
                    ? "Tenant evidence verified"
                    : "Integrity anomaly detected"}
                </div>

                <div className="mt-1 text-[10px] font-mono text-slate-500">
                  checked events=
                  {verification.chain_length} ·
                  nodes=
                  {verification.nodes_checked} ·
                  edges=
                  {verification.edges_checked}
                </div>
              </div>
            </div>
          </div>
        )}

        {graph ? (
          <div className="grid gap-5 xl:grid-cols-[1.1fr_0.9fr]">
            <EvidenceGraph
              nodes={graph.nodes}
              edges={graph.edges}
              truncated={graph.truncated}
              selectedId={
                selected?.evidence_id
              }
              onSelect={(node) =>
                setSelected(node)
              }
            />

            <section className="border border-cyan-500/10 bg-black/40">
              <div className="border-b border-cyan-500/10 px-4 py-3">
                <div className="text-[10px] font-mono uppercase tracking-[0.25em] text-cyan-400">
                  Causal evidence
                </div>

                <div className="mt-1 text-[9px] font-mono text-slate-600">
                  {graph.nodes.length} nodes ·{" "}
                  {graph.edges.length} edges
                  {graph.truncated
                    ? " · bounded"
                    : ""}
                </div>
              </div>

              {selected && (
                <div className="space-y-4 px-4 py-4">
                  <Info
                    label="Evidence ID"
                    value={
                      selected.evidence_id
                    }
                  />

                  <Info
                    label="Security event"
                    value={
                      selected.security_event_id ??
                      "none"
                    }
                  />

                  <Info
                    label="Trace"
                    value={
                      selected.trace_id ||
                      "—"
                    }
                  />

                  <Info
                    label="Node type"
                    value={
                      selected.node_type
                    }
                  />

                  <Info
                    label="Source"
                    value={
                      selected.source
                    }
                  />

                  <Info
                    label="Artifact hash"
                    value={
                      selected.artifact_hash
                    }
                  />

                  <Info
                    label="Action"
                    value={String(
                      selected
                        .metadata_redacted
                        ?.action_taken ??
                        "—"
                    )}
                  />

                  <Info
                    label="Threat"
                    value={String(
                      selected
                        .metadata_redacted
                        ?.threat_category ??
                        "—"
                    )}
                  />

                  <Info
                    label="Created"
                    value={
                      new Date(
                        selected.created_at
                      ).toLocaleString()
                    }
                  />
                </div>
              )}
            </section>
          </div>
        ) : (
          <div className="border border-cyan-500/10 bg-black/40 px-6 py-24 text-center">
            <ShieldCheck className="mx-auto h-8 w-8 text-slate-700" />
            <div className="mt-4 text-[10px] font-mono uppercase tracking-[0.24em] text-slate-600">
              Enter an evidence UUID to begin investigation
            </div>
          </div>
        )}
      </div>
    </main>
  );
}

function Info({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div>
      <div className="mb-1 text-[8px] font-mono uppercase tracking-[0.2em] text-slate-700">
        {label}
      </div>
      <div className="break-all text-[10px] font-mono leading-relaxed text-slate-400">
        {value}
      </div>
    </div>
  );
}