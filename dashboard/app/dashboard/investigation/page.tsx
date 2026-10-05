"use client";

import Link from "next/link";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Clock3,
  FileCheck2,
  PlayCircle,
  Search,
  ShieldAlert,
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
  type EvidenceReplay,
  type EvidenceTrace,
  fetchEvidenceGraph,
  fetchEvidenceNode,
  fetchEvidenceReplay,
  fetchEvidenceTrace,
  verifyEvidence,
} from "@/lib/evidence-client";

type InvestigationMode =
  | "evidence"
  | "trace";

export default function InvestigationPage() {
  const params =
    useSearchParams();

  const initialEvidence =
    params.get("evidence") ?? "";

  const initialTrace =
    params.get("trace") ?? "";

  const [mode, setMode] =
    useState<InvestigationMode>(
      initialTrace
        ? "trace"
        : "evidence"
    );

  const [input, setInput] =
    useState(
      initialTrace ||
        initialEvidence
    );

  const [selected, setSelected] =
    useState<EvidenceNode | null>(
      null
    );

  const [graph, setGraph] =
    useState<GraphData | null>(
      null
    );

  const [trace, setTrace] =
    useState<EvidenceTrace | null>(
      null
    );

  const [replay, setReplay] =
    useState<EvidenceReplay | null>(
      null
    );

  const [verification, setVerification] =
    useState<Awaited<
      ReturnType<
        typeof verifyEvidence
      >
    > | null>(null);

  const [loading, setLoading] =
    useState(false);

  const [error, setError] =
    useState<string | null>(
      null
    );

  useEffect(() => {
    const initialTarget =
      initialTrace ||
      initialEvidence;

    if (!initialTarget) {
      return;
    }

    // Initial URL-driven investigation.
    // The actual investigation operation intentionally owns its state
    // transitions because it is asynchronous.

    void investigate(
      initialTarget,
      initialTrace
        ? "trace"
        : "evidence"
    );

    // URL parameters are intentionally the only trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    initialEvidence,
    initialTrace,
  ]);

  async function investigate(
    target = input,
    selectedMode = mode
  ) {
    const normalized =
      target.trim();

    if (!normalized) {
      setError(
        selectedMode ===
          "evidence"
          ? "Enter an evidence UUID."
          : "Enter a trace ID."
      );
      return;
    }

    setLoading(true);
    setError(null);
    setTrace(null);
    setReplay(null);
    setVerification(null);

    try {
      let traceId =
        "";

      let evidenceNode:
        | EvidenceNode
        | null = null;

      if (
        selectedMode ===
        "evidence"
      ) {
        evidenceNode =
          await fetchEvidenceNode(
            normalized
          );

        traceId =
          evidenceNode.trace_id;

        setSelected(
          evidenceNode
        );
      } else {
        traceId =
          normalized;

        const reconstructed =
          await fetchEvidenceTrace(
            traceId,
            250
          );

        setTrace(
          reconstructed
        );

        const firstEvidence =
          reconstructed.records.find(
            (record) =>
              record.evidence_id
                !== null
          );

        if (
          firstEvidence?.evidence_id
        ) {
          evidenceNode =
            await fetchEvidenceNode(
              firstEvidence.evidence_id
            );

          setSelected(
            evidenceNode
          );
        }
      }

      const [
        traceData,
        replayData,
      ] = await Promise.all([
        fetchEvidenceTrace(
          traceId,
          250
        ),
        fetchEvidenceReplay(
          traceId,
          250
        ),
      ]);

      setTrace(
        traceData
      );

      setReplay(
        replayData
      );

      if (
        evidenceNode
      ) {
        const graphData =
          await fetchEvidenceGraph(
            evidenceNode.evidence_id,
            4,
            150
          );

        setGraph(
          graphData
        );
      } else {
        setGraph(null);
      }
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Investigation failed"
      );

      setSelected(null);
      setGraph(null);
      setTrace(null);
      setReplay(null);
    } finally {
      setLoading(false);
    }
  }

  async function selectNode(
    node: EvidenceNode
  ) {
    setSelected(node);

    try {
      const [
        graphData,
        traceData,
        replayData,
      ] = await Promise.all([
        fetchEvidenceGraph(
          node.evidence_id,
          4,
          150
        ),
        fetchEvidenceTrace(
          node.trace_id,
          250
        ),
        fetchEvidenceReplay(
          node.trace_id,
          250
        ),
      ]);

      setGraph(
        graphData
      );

      setTrace(
        traceData
      );

      setReplay(
        replayData
      );

      setMode(
        "evidence"
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to load evidence context"
      );
    }
  }

  async function runVerification() {
    setError(null);

    try {
      const result =
        await verifyEvidence();

      setVerification(
        result
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Verification failed"
      );
    }
  }

  const integrityLabel =
    trace?.integrity.status ===
    "verified"
      ? "Trace verified"
      : trace?.integrity.status ===
          "partial"
        ? "Trace partially verified"
        : trace?.integrity.status ===
            "invalid"
          ? "Trace integrity failure"
          : "Not evaluated";

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
              Trace reconstruction · forensic replay ·
              tenant scoped
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
        <section className="border border-cyan-500/10 bg-black/40 p-4">
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() =>
                setMode("evidence")
              }
              className={`border px-3 py-2 text-[9px] font-mono uppercase tracking-[0.16em] ${
                mode === "evidence"
                  ? "border-cyan-400/40 text-cyan-400"
                  : "border-slate-800 text-slate-600"
              }`}
            >
              Evidence ID
            </button>

            <button
              type="button"
              onClick={() =>
                setMode("trace")
              }
              className={`border px-3 py-2 text-[9px] font-mono uppercase tracking-[0.16em] ${
                mode === "trace"
                  ? "border-cyan-400/40 text-cyan-400"
                  : "border-slate-800 text-slate-600"
              }`}
            >
              Trace ID
            </button>
          </div>

          <div className="mt-3 grid gap-3 lg:grid-cols-[1fr_auto]">
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
                    event.key ===
                    "Enter"
                  ) {
                    void investigate();
                  }
                }}
                placeholder={
                  mode ===
                  "evidence"
                    ? "Evidence UUID"
                    : "Trace ID"
                }
                className="w-full bg-transparent py-3 text-xs font-mono text-slate-200 outline-none placeholder:text-slate-700"
              />
            </div>

            <button
              type="button"
              onClick={() =>
                void investigate()
              }
              disabled={loading}
              className="flex items-center justify-center gap-2 border border-cyan-400/30 px-5 py-3 text-[10px] font-mono uppercase tracking-[0.18em] text-cyan-400 hover:bg-cyan-500/5 disabled:opacity-40"
            >
              <Search className="h-3.5 w-3.5" />

              {loading
                ? "Investigating…"
                : "Investigate"}
            </button>
          </div>
        </section>

        {error && (
          <div className="flex items-center gap-2 border border-rose-500/20 bg-rose-500/5 px-4 py-3 text-xs font-mono text-rose-300">
            <AlertTriangle className="h-4 w-4" />
            {error}
          </div>
        )}

        {trace && (
          <section className="grid gap-3 md:grid-cols-4">
            <Metric
              label="Events"
              value={String(
                trace.event_count
              )}
            />

            <Metric
              label="Evidence"
              value={String(
                trace.node_count
              )}
            />

            <Metric
              label="Causal edges"
              value={String(
                trace.edge_count
              )}
            />

            <Metric
              label="Integrity"
              value={
                integrityLabel
              }
            />
          </section>
        )}

        {replay && (
          <section className="border border-emerald-500/10 bg-black/40">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-emerald-500/10 px-4 py-3">
              <div>
                <div className="flex items-center gap-2 text-[10px] font-mono uppercase tracking-[0.24em] text-emerald-400">
                  <PlayCircle className="h-4 w-4" />
                  Forensic replay
                </div>

                <div className="mt-1 text-[9px] font-mono text-slate-600">
                  Historical reconstruction only · no
                  actions executed
                </div>
              </div>

              <div className="flex items-center gap-3 text-[8px] font-mono uppercase">
                <span className="border border-emerald-500/20 px-2 py-1 text-emerald-400">
                  read-only
                </span>

                <span className="border border-slate-800 px-2 py-1 text-slate-600">
                  mutations=0
                </span>
              </div>
            </div>

            <div className="divide-y divide-slate-900/80">
              {replay.records.map(
                (record) => (
                  <div
                    key={`${record.event_id}:${record.sequence}`}
                    className="grid gap-3 px-4 py-4 lg:grid-cols-[90px_1fr_auto]"
                  >
                    <div className="text-[9px] font-mono text-slate-700">
                      STEP{" "}
                      {String(
                        record.sequence
                      ).padStart(
                        3,
                        "0"
                      )}
                    </div>

                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[10px] font-mono text-slate-300">
                          {record.action_taken}
                        </span>

                        <span className="border border-slate-800 px-2 py-0.5 text-[8px] font-mono uppercase text-slate-600">
                          {
                            record.threat_category
                          }
                        </span>

                        {record.evidence_hash_valid &&
                          record.record_hash_valid && (
                            <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                          )}
                      </div>

                      <div className="mt-2 text-[8px] font-mono text-slate-700">
                        {new Date(
                          record.timestamp
                        ).toLocaleString()}
                      </div>

                      <div className="mt-1 break-all text-[8px] font-mono text-slate-800">
                        {record.event_id}
                      </div>
                    </div>

                    <div className="text-right text-[8px] font-mono text-slate-700">
                      {record.node_type ??
                        "no-evidence"}
                    </div>
                  </div>
                )
              )}
            </div>

            {replay.truncated && (
              <div className="flex items-center gap-2 border-t border-amber-500/10 bg-amber-500/5 px-4 py-3 text-[9px] font-mono uppercase text-amber-300">
                <ShieldAlert className="h-3.5 w-3.5" />
                Replay bounded; additional steps omitted
              </div>
            )}
          </section>
        )}

        {trace && trace.records.length > 0 && (
          <section className="border border-slate-800 bg-black/30">
            <div className="border-b border-slate-900 px-4 py-3">
              <div className="flex items-center gap-2 text-[10px] font-mono uppercase tracking-[0.25em] text-slate-500">
                <Clock3 className="h-3.5 w-3.5" />
                Reconstructed timeline
              </div>
            </div>

            <div className="overflow-auto">
              <table className="w-full min-w-[920px] border-collapse">
                <thead>
                  <tr className="border-b border-slate-900 text-left text-[8px] font-mono uppercase tracking-[0.18em] text-slate-700">
                    <th className="px-4 py-3">
                      Step
                    </th>
                    <th className="px-4 py-3">
                      Time
                    </th>
                    <th className="px-4 py-3">
                      Action
                    </th>
                    <th className="px-4 py-3">
                      Threat
                    </th>
                    <th className="px-4 py-3">
                      Evidence
                    </th>
                    <th className="px-4 py-3">
                      Integrity
                    </th>
                  </tr>
                </thead>

                <tbody>
                  {trace.records.map(
                    (record) => {
                      const valid =
                        record.record_hash_valid &&
                        (
                          record.evidence_id ===
                            null ||
                          record.evidence_hash_valid
                        );

                      return (
                        <tr
                          key={`timeline:${record.event_id}`}
                          className="border-b border-slate-900/80 text-[9px] font-mono"
                        >
                          <td className="px-4 py-3 text-slate-700">
                            {record.sequence}
                          </td>

                          <td className="px-4 py-3 text-slate-600">
                            {new Date(
                              record.timestamp
                            ).toLocaleString()}
                          </td>

                          <td className="px-4 py-3 text-slate-400">
                            {record.action_taken}
                          </td>

                          <td className="px-4 py-3 text-slate-600">
                            {
                              record.threat_category
                            }
                          </td>

                          <td className="px-4 py-3 text-slate-700">
                            {record.evidence_id
                              ? record.evidence_id.slice(
                                  0,
                                  12
                                ) + "…"
                              : "none"}
                          </td>

                          <td className="px-4 py-3">
                            {valid ? (
                              <span className="flex items-center gap-1 text-emerald-400">
                                <CheckCircle2 className="h-3 w-3" />
                                valid
                              </span>
                            ) : (
                              <span className="flex items-center gap-1 text-rose-400">
                                <ShieldAlert className="h-3 w-3" />
                                invalid
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    }
                  )}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {graph && (
          <div className="grid gap-5 xl:grid-cols-[1.1fr_0.9fr]">
            <EvidenceGraph
              nodes={graph.nodes}
              edges={graph.edges}
              truncated={
                graph.truncated
              }
              selectedId={
                selected?.evidence_id
              }
              onSelect={(node) =>
                void selectNode(
                  node
                )
              }
            />

            <section className="border border-cyan-500/10 bg-black/40">
              <div className="border-b border-cyan-500/10 px-4 py-3">
                <div className="text-[10px] font-mono uppercase tracking-[0.25em] text-cyan-400">
                  Evidence context
                </div>
              </div>

              {selected ? (
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
                      selected.metadata_redacted
                        ?.action_taken ??
                        "—"
                    )}
                  />

                  <Info
                    label="Threat"
                    value={String(
                      selected.metadata_redacted
                        ?.threat_category ??
                        "—"
                    )}
                  />

                  <Link
                    href={`/dashboard/investigation?trace=${encodeURIComponent(
                      selected.trace_id
                    )}`}
                    className="flex items-center justify-center gap-2 border border-cyan-400/20 px-3 py-2 text-[9px] font-mono uppercase tracking-[0.15em] text-cyan-400 hover:bg-cyan-500/5"
                  >
                    <FileCheck2 className="h-3.5 w-3.5" />
                    Open trace
                  </Link>
                </div>
              ) : (
                <div className="px-4 py-16 text-center text-[9px] font-mono uppercase tracking-[0.18em] text-slate-700">
                  Select evidence from the graph
                </div>
              )}
            </section>
          </div>
        )}

        {!loading &&
          !trace &&
          !graph && (
            <div className="border border-cyan-500/10 bg-black/40 px-6 py-24 text-center">
              <ShieldCheck className="mx-auto h-8 w-8 text-slate-700" />

              <div className="mt-4 text-[10px] font-mono uppercase tracking-[0.24em] text-slate-600">
                Enter an evidence ID or trace ID to
                begin investigation
              </div>
            </div>
          )}

        {verification && (
          <section
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
                  events=
                  {verification.chain_length} ·
                  nodes=
                  {verification.nodes_checked} ·
                  edges=
                  {verification.edges_checked}
                </div>
              </div>
            </div>
          </section>
        )}

        <div className="flex justify-end">
          <button
            type="button"
            onClick={() =>
              void runVerification()
            }
            className="flex items-center gap-2 border border-emerald-400/20 px-4 py-3 text-[9px] font-mono uppercase tracking-[0.16em] text-emerald-400 hover:bg-emerald-500/5"
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            Verify tenant evidence
          </button>
        </div>
      </div>
    </main>
  );
}

function Metric({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="border border-slate-900 bg-black/40 px-4 py-4">
      <div className="text-[8px] font-mono uppercase tracking-[0.2em] text-slate-700">
        {label}
      </div>

      <div className="mt-2 break-all text-[11px] font-mono text-slate-400">
        {value}
      </div>
    </div>
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
