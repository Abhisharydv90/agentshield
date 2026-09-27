"use client";

import { useState } from "react";
import {
  Key,
  Copy,
  CheckCircle2,
  Zap,
  Loader2,
  AlertCircle,
  ShieldCheck,
  ArrowRight,
} from "lucide-react";

type TestResult =
  | { state: "idle" }
  | { state: "testing" }
  | { state: "ok"; latency: number; total: number }
  | { state: "error"; message: string };

/**
 * Shows the API key ONCE after signup, with a live tester that
 * fires a real request to /api/metrics using the key.
 */
export function ApiKeyReveal({
  apiKey,
  onContinue,
}: {
  apiKey: string;
  onContinue: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const [test, setTest] = useState<TestResult>({ state: "idle" });

  function copyKey() {
    navigator.clipboard.writeText(apiKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }

  async function runTest() {
    setTest({ state: "testing" });
    const start = performance.now();
    try {
      const res = await fetch("/api/metrics", {
        headers: { "X-API-Key": apiKey },
        cache: "no-store",
      });
      const latency = Math.round(performance.now() - start);

      if (!res.ok) {
        setTest({ state: "error", message: `HTTP ${res.status}` });
        return;
      }
      const data = await res.json();
      setTest({
        state: "ok",
        latency,
        total: data.total_events ?? 0,
      });
    } catch (e) {
      setTest({ state: "error", message: String(e) });
    }
  }

  return (
    <div className="relative bg-black/80 backdrop-blur-2xl border border-emerald-500/30 p-7">
      <span className="absolute top-0 left-0 w-3 h-3 border-l-2 border-t-2 border-emerald-500/60" />
      <span className="absolute top-0 right-0 w-3 h-3 border-r-2 border-t-2 border-emerald-500/60" />
      <span className="absolute bottom-0 left-0 w-3 h-3 border-l-2 border-b-2 border-emerald-500/60" />
      <span className="absolute bottom-0 right-0 w-3 h-3 border-r-2 border-b-2 border-emerald-500/60" />

      <div className="flex items-center gap-2 mb-5">
        <div className="w-6 h-6 rounded-sm bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
        </div>
        <h1 className="text-sm font-mono tracking-[0.28em] uppercase text-slate-200">
          Workspace Live
        </h1>
      </div>

      <p className="text-[11px] font-mono text-slate-400 leading-relaxed mb-6">
        Your tenant is provisioned and the audit chain is sealed. Copy your API
        key now — it will{" "}
        <span className="text-emerald-400">never be shown again</span>.
      </p>

      {/* API Key */}
      <div className="relative bg-black/60 border border-emerald-500/30 p-3.5 mb-4">
        <div className="flex items-center gap-2 mb-2">
          <Key className="w-3 h-3 text-emerald-400" />
          <span className="text-[9px] font-mono tracking-widest text-slate-500 uppercase">
            API Key · Live Environment
          </span>
        </div>
        <div className="font-mono text-[10px] text-emerald-300 break-all leading-relaxed">
          {apiKey}
        </div>
      </div>

      {/* Copy button */}
      <button
        onClick={copyKey}
        className="w-full bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/50 text-emerald-300 py-2.5 text-[11px] font-mono tracking-[0.25em] uppercase transition-colors flex items-center justify-center gap-2 mb-4"
      >
        {copied ? (
          <>
            <CheckCircle2 className="w-3.5 h-3.5" />
            Copied to clipboard
          </>
        ) : (
          <>
            <Copy className="w-3.5 h-3.5" />
            Copy API key
          </>
        )}
      </button>

      {/* Live tester */}
      <div className="relative bg-black/60 border border-emerald-500/15 p-3.5 mb-5">
        <div className="flex items-center justify-between mb-3">
          <span className="text-[9px] font-mono tracking-widest text-slate-500 uppercase">
            Live key test
          </span>
          <button
            onClick={runTest}
            disabled={test.state === "testing"}
            className="text-[10px] font-mono tracking-wider text-emerald-400 hover:text-emerald-300 transition-colors disabled:opacity-40"
          >
            {test.state === "testing" ? (
              <span className="flex items-center gap-1.5">
                <Loader2 className="w-3 h-3 animate-spin" />
                testing…
              </span>
            ) : (
              <span className="flex items-center gap-1.5">
                <Zap className="w-3 h-3" />
                {test.state === "idle" ? "Run test" : "Re-run"}
              </span>
            )}
          </button>
        </div>

        {test.state === "idle" && (
          <div className="text-[10px] font-mono text-slate-600 leading-relaxed">
            Fire a real request to your gateway to confirm the key works.
          </div>
        )}

        {test.state === "testing" && (
          <div className="text-[10px] font-mono text-amber-400">
            → GET /api/metrics · sending X-API-Key header
          </div>
        )}

        {test.state === "ok" && (
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 text-emerald-400 text-[10px] font-mono">
              <CheckCircle2 className="w-3 h-3" />
              <span>200 OK · workspace reachable</span>
            </div>
            <div className="text-[10px] font-mono text-slate-500">
              latency: {test.latency}ms · events: {test.total}
            </div>
          </div>
        )}

        {test.state === "error" && (
          <div className="flex items-start gap-2 text-rose-400 text-[10px] font-mono">
            <AlertCircle className="w-3 h-3 shrink-0 mt-0.5" />
            <span>Request failed: {test.message}</span>
          </div>
        )}
      </div>

      {/* Continue button */}
      <button
        onClick={onContinue}
        className="w-full bg-emerald-500 hover:bg-emerald-400 text-black py-3 text-[11px] font-mono tracking-[0.3em] uppercase font-bold transition-colors flex items-center justify-center gap-2"
      >
        Enter dashboard
        <ArrowRight className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}