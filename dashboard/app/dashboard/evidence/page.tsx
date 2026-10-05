"use client";

import Link from "next/link";
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  ExternalLink,
  RefreshCw,
  Search,
  ShieldCheck,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useState,
} from "react";

import {
  EvidenceGraph,
} from "@/components/evidence/evidence-graph";

import {
  type EvidenceNode,
  type EvidencePage,
  type EvidenceVerification,
  exportEvidence,
  fetchEvidenceGraph,
  fetchEvidencePage,
  verifyEvidence,
} from "@/lib/evidence-client";

export default function EvidencePage() {
  const [page, setPage] =
    useState<EvidencePage | null>(null);

  const [selected, setSelected] =
    useState<EvidenceNode | null>(null);

  const [graph, setGraph] =
    useState<{
      nodes: EvidenceNode[];
      edges: {
        edge_id: string;
        tenant_id: string;
        trace_id: string;
        from_evidence_id: string;
        to_evidence_id: string;
        relation: string;
        created_at: string;
      }[];
    } | null>(null);

  const [verification, setVerification] =
    useState<EvidenceVerification | null>(
      null
    );

  const [traceId, setTraceId] =
    useState("");

  const [nodeType, setNodeType] =
    useState("");

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<string | null>(null);

  const load = useCallback(
    async (cursor?: string) => {
      setLoading(true);
      setError(null);

      try {
        const next = await fetchEvidencePage(
          {
            traceId:
              traceId || undefined,
            nodeType:
              nodeType || undefined,
            pageSize: 50,
            cursor,
          }
        );

        setPage(next);

        if (!cursor && next.nodes.length > 0) {
          setSelected(
            next.nodes[0]
          );

          const graphData =
            await fetchEvidenceGraph(
              next.nodes[0].evidence_id,
              2,
              100
            );

          setGraph({
            nodes: graphData.nodes,
            edges: graphData.edges,
          });
        }
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Failed to load evidence"
        );
      } finally {
        setLoading(false);
      }
    },
    [traceId, nodeType]
  );

  useEffect(() => {
  let cancelled = false;

  const run = async () => {
    if (cancelled) return;
    await load();
  };

  void run();

  return () => {
    cancelled = true;
  };
}, [load]);

  async function selectNode(
    node: EvidenceNode
  ) {
    setSelected(node);

    try {
      const graphData =
        await fetchEvidenceGraph(
          node.evidence_id,
          2,
          100
        );

      setGraph({
        nodes: graphData.nodes,
        edges: graphData.edges,
      });
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to load graph"
      );
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

  async function downloadExport() {
    setError(null);

    try {
      const blob =
        await exportEvidence(1000);

      const url =
        URL.createObjectURL(blob);

      const anchor =
        document.createElement("a");

      anchor.href = url;
      anchor.download = `agentshield-evidence-${Date.now()}.json`;
      anchor.click();

      URL.revokeObjectURL(url);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Export failed"
      );
    }
  }

  return (
    <main className="min-h-screen bg-black text-slate-200">
      <div className="border-b border-emerald-500/10 bg-black/80 px-6 py-4">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
              <h1 className="text-sm font-mono tracking-[0.28em] uppercase text-emerald-400">
                Evidence Control Plane
              </h1>
            </div>
            <div className="mt-1 text-[9px] font-mono text-slate-600">
              7F-5 · 7F-6 · 7G · 7H · 7J · 7K
            </div>
          </div>

          <div className="flex items-center gap-2 text-[9px] font-mono uppercase">
            <Link
              href="/dashboard"
              className="border border-emerald-500/15 px-3 py-2 text-slate-500 hover:border-emerald-400/30 hover:text-emerald-400"
            >
              Core
            </Link>

            <Link
              href="/dashboard/investigation"
              className="border border-cyan-500/20 px-3 py-2 text-cyan-400 hover:border-cyan-400/40"
            >
              Investigation
            </Link>
          </div>
        </div>
      </div>

      <div className="mx-auto max-w-7xl space-y-5 px-6 py-6">
        <div className="grid gap-3 lg:grid-cols-[1fr_180px_180px_auto_auto]">
          <div className="flex items-center gap-2 border border-emerald-500/15 bg-black/50 px-3">
            <Search className="h-3.5 w-3.5 text-slate-600" />
            <input
              value={traceId}
              onChange={(event) =>
                setTraceId(
                  event.target.value
                )
              }
              placeholder="Trace ID"
              className="w-full bg-transparent py-3 text-xs font-mono text-slate-200 outline-none placeholder:text-slate-700"
            />
          </div>

          <input
            value={nodeType}
            onChange={(event) =>
              setNodeType(
                event.target.value
              )
            }
            placeholder="Node type"
            className="border border-emerald-500/15 bg-black/50 px-3 py-3 text-xs font-mono text-slate-200 outline-none placeholder:text-slate-700"
          />

          <button
            onClick={() => void load()}
            className="flex items-center justify-center gap-2 border border-emerald-400/25 bg-emerald-500/5 px-3 py-3 text-[10px] font-mono uppercase tracking-[0.18em] text-emerald-400 hover:bg-emerald-500/10"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Search
          </button>

          <button
            onClick={() =>
              void runVerification()
            }
            className="flex items-center justify-center gap-2 border border-cyan-400/20 px-3 py-3 text-[10px] font-mono uppercase tracking-[0.18em] text-cyan-400 hover:bg-cyan-500/5"
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            Verify
          </button>

          <button
            onClick={() =>
              void downloadExport()
            }
            className="flex items-center justify-center gap-2 border border-slate-700 px-3 py-3 text-[10px] font-mono uppercase tracking-[0.18em] text-slate-400 hover:border-slate-500 hover:text-slate-200"
          >
            <Download className="h-3.5 w-3.5" />
            Export
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
                    ? "Evidence integrity verified"
                    : "Evidence integrity failure"}
                </div>

                <div className="mt-1 text-[10px] font-mono text-slate-500">
                  chain={verification.chain_valid ? "valid" : "broken"} ·
                  events={verification.chain_length} ·
                  nodes={verification.nodes_checked} ·
                  edges={verification.edges_checked}
                </div>
              </div>
            </div>

            {verification.issues.length > 0 && (
              <div className="mt-4 space-y-1">
                {verification.issues
                  .slice(0, 8)
                  .map((issue) => (
                    <div
                      key={`${issue.code}:${issue.detail}`}
                      className="text-[9px] font-mono text-rose-300/80"
                    >
                      {issue.code} · {issue.detail}
                    </div>
                  ))}
              </div>
            )}
          </div>
        )}

        <div className="grid gap-5 xl:grid-cols-[1.2fr_1fr]">
          <section className="border border-emerald-500/10 bg-black/40">
            <div className="border-b border-emerald-500/10 px-4 py-3">
              <div className="text-[10px] font-mono uppercase tracking-[0.25em] text-slate-500">
                Evidence nodes
              </div>
            </div>

            <div className="overflow-auto">
              <table className="w-full min-w-[760px] border-collapse">
                <thead>
                  <tr className="border-b border-emerald-500/10 text-left text-[8px] font-mono uppercase tracking-[0.2em] text-slate-700">
                    <th className="px-4 py-3">
                      Evidence
                    </th>
                    <th className="px-4 py-3">
                      Type
                    </th>
                    <th className="px-4 py-3">
                      Source
                    </th>
                    <th className="px-4 py-3">
                      Trace
                    </th>
                    <th className="px-4 py-3">
                      Time
                    </th>
                  </tr>
                </thead>

                <tbody>
                  {page?.nodes.map((node) => {
                    const active =
                      selected?.evidence_id ===
                      node.evidence_id;

                    return (
                      <tr
                        key={node.evidence_id}
                        onClick={() =>
                          void selectNode(
                            node
                          )
                        }
                        className={`cursor-pointer border-b border-emerald-500/5 text-[9px] font-mono transition ${
                          active
                            ? "bg-emerald-500/5"
                            : "hover:bg-emerald-500/[0.03]"
                        }`}
                      >
                        <td className="px-4 py-3">
                          <div className="text-emerald-400">
                            {node.evidence_id.slice(
                              0,
                              12
                            )}
                            …
                          </div>
                          <div className="mt-1 text-slate-700">
                            {node.artifact_hash.slice(
                              0,
                              16
                            )}
                            …
                          </div>
                        </td>

                        <td className="px-4 py-3 text-slate-400">
                          {node.node_type}
                        </td>

                        <td className="px-4 py-3 text-slate-500">
                          {node.source}
                        </td>

                        <td className="max-w-[170px] truncate px-4 py-3 text-slate-600">
                          {node.trace_id || "—"}
                        </td>

                        <td className="px-4 py-3 text-slate-600">
                          {new Date(
                            node.created_at
                          ).toLocaleString()}
                        </td>
                      </tr>
                    );
                  })}

                  {!loading &&
                    page?.nodes.length === 0 && (
                      <tr>
                        <td
                          colSpan={5}
                          className="px-4 py-16 text-center text-[10px] font-mono text-slate-700"
                        >
                          NO EVIDENCE MATCHED
                        </td>
                      </tr>
                    )}
                </tbody>
              </table>
            </div>

            {page?.has_more && (
              <div className="flex justify-end border-t border-emerald-500/10 p-3">
                <button
                  onClick={() =>
                    void load(
                      page.next_cursor ??
                        undefined
                    )
                  }
                  className="flex items-center gap-2 border border-emerald-500/20 px-3 py-2 text-[9px] font-mono uppercase tracking-[0.18em] text-emerald-400"
                >
                  Next page
                </button>
              </div>
            )}
          </section>

          <div className="space-y-5">
            {graph && (
              <EvidenceGraph
                nodes={graph.nodes}
                edges={graph.edges}
                selectedId={
                  selected?.evidence_id
                }
                onSelect={(node) =>
                  void selectNode(
                    node
                  )
                }
              />
            )}

            {selected && (
              <section className="border border-cyan-500/10 bg-black/40">
                <div className="flex items-center justify-between border-b border-cyan-500/10 px-4 py-3">
                  <div className="text-[10px] font-mono uppercase tracking-[0.25em] text-cyan-400">
                    Selected evidence
                  </div>

                  <Link
                    href={`/dashboard/investigation?evidence=${selected.evidence_id}`}
                    className="flex items-center gap-1 text-[9px] font-mono uppercase tracking-[0.15em] text-slate-500 hover:text-cyan-400"
                  >
                    Investigate
                    <ExternalLink className="h-3 w-3" />
                  </Link>
                </div>

                <div className="space-y-3 px-4 py-4 text-[10px] font-mono">
                  <Field
                    label="Evidence ID"
                    value={
                      selected.evidence_id
                    }
                  />
                  <Field
                    label="Trace"
                    value={
                      selected.trace_id ||
                      "—"
                    }
                  />
                  <Field
                    label="Artifact hash"
                    value={
                      selected.artifact_hash
                    }
                  />
                  <Field
                    label="Record hash"
                    value={
                      String(
                        selected.metadata_redacted
                          ?.record_hash ??
                          "—"
                      )
                    }
                  />
                  <Field
                    label="Action"
                    value={
                      String(
                        selected.metadata_redacted
                          ?.action_taken ??
                          "—"
                      )
                    }
                  />
                </div>
              </section>
            )}
          </div>
        </div>
      </div>
    </main>
  );
}

function Field({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div>
      <div className="mb-1 text-[8px] uppercase tracking-[0.2em] text-slate-700">
        {label}
      </div>
      <div className="break-all text-slate-400">
        {value}
      </div>
    </div>
  );
}