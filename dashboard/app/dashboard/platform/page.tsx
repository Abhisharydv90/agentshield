"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  Bot,
  Boxes,
  Brain,
  Cable,
  ClipboardCheck,
  Database,
  FileSearch,
  Gauge,
  Layers3,
  LockKeyhole,
  Network,
  RefreshCw,
  ShieldCheck,
  Workflow,
} from "lucide-react";

type Probe = {
  status: "checking" | "online" | "degraded" | "offline";
  detail: string;
};

const modules = [
  {
    name: "Agent development",
    description: "Create agents, manage lifecycle, capabilities, templates and versions.",
    href: "/dashboard/agents",
    icon: Bot,
    phase: "Phase 1",
    state: "Available",
  },
  {
    name: "Deployments",
    description: "Declare agent versions, environments, regions and desired replicas.",
    href: "/dashboard/deployments",
    icon: Boxes,
    phase: "Runtime",
    state: "Available",
  },
  {
    name: "Evidence & audit",
    description: "Inspect security evidence, integrity commitments and audit records.",
    href: "/dashboard/evidence",
    icon: ClipboardCheck,
    phase: "Phase 8",
    state: "Available",
  },
  {
    name: "Investigation",
    description: "Explore incident timelines, causal relationships and forensic views.",
    href: "/dashboard/investigation",
    icon: FileSearch,
    phase: "Phase 10",
    state: "Available",
  },
  {
    name: "Trust & policy",
    description: "Trust decisions, identity, capabilities, approvals and policy enforcement.",
    href: "/dashboard/platform#trust",
    icon: ShieldCheck,
    phase: "Phase 4",
    state: "API surface",
  },
  {
    name: "Tool fabric",
    description: "Tool contracts, registry, MCP boundaries, browser policy and secrets.",
    href: "/dashboard/platform#tools",
    icon: Cable,
    phase: "Phase 5",
    state: "API surface",
  },
  {
    name: "Memory fabric",
    description: "Tenant-scoped memory, provenance, integrity, retention and retrieval.",
    href: "/dashboard/platform#memory",
    icon: Brain,
    phase: "Phase 6",
    state: "API surface",
  },
  {
    name: "Isolation fabric",
    description: "Sandbox execution, filesystem policy, network egress and resource quotas.",
    href: "/dashboard/platform#isolation",
    icon: LockKeyhole,
    phase: "Phase 7",
    state: "API surface",
  },
  {
    name: "Security lab",
    description: "Deterministic adversarial scenarios, fuzzing and regression reports.",
    href: "/dashboard/platform#lab",
    icon: Activity,
    phase: "Phase 9",
    state: "API surface",
  },
  {
    name: "Control plane",
    description: "Organization administration, RBAC/ABAC, configuration and usage.",
    href: "/dashboard/platform#control-plane",
    icon: Gauge,
    phase: "Phase 11",
    state: "API surface",
  },
  {
    name: "Ecosystem",
    description: "Plugin, MCP, A2A and integration descriptors.",
    href: "/dashboard/platform#ecosystem",
    icon: Network,
    phase: "Phase 12",
    state: "API surface",
  },
  {
    name: "Scale & workflows",
    description: "Worker coordination contracts, sharding, events and workflow durability.",
    href: "/dashboard/platform#scale",
    icon: Workflow,
    phase: "Phase 13",
    state: "API surface",
  },
  {
    name: "Enterprise",
    description: "SSO trust configuration, retention, SIEM, KMS descriptors and compliance.",
    href: "/dashboard/platform#enterprise",
    icon: Database,
    phase: "Phase 14",
    state: "API surface",
  },
  {
    name: "Research",
    description: "Authority conservation, provenance-conditioned policy and decision proofs.",
    href: "/dashboard/platform#research",
    icon: Layers3,
    phase: "Phase 15",
    state: "API surface",
  },
];

function StatusPill({ value }: { value: Probe["status"] }) {
  const styles: Record<Probe["status"], string> = {
    checking: "border-slate-700 text-slate-400",
    online: "border-emerald-500/30 text-emerald-300",
    degraded: "border-amber-500/30 text-amber-300",
    offline: "border-rose-500/30 text-rose-300",
  };
  return (
    <span className={`rounded-full border px-2.5 py-1 text-xs capitalize ${styles[value]}`}>
      {value}
    </span>
  );
}

export default function PlatformHubPage() {
  const [health, setHealth] = useState<Probe>({
    status: "checking",
    detail: "Checking API health…",
  });
  const [readiness, setReadiness] = useState<Probe>({
    status: "checking",
    detail: "Checking database, cache and runtime…",
  });
  const [checkedAt, setCheckedAt] = useState<string>("");

  const refresh = useCallback(async () => {
    setHealth({ status: "checking", detail: "Checking API health…" });
    setReadiness({ status: "checking", detail: "Checking database, cache and runtime…" });

    try {
      const response = await fetch("/health", {
        cache: "no-store",
        credentials: "include",
      });
      if (!response.ok) throw new Error(`Health endpoint returned ${response.status}`);
      const body = await response.json();
      setHealth({
        status: body.status === "ok" ? "online" : "degraded",
        detail: `${body.platform ?? "API"} · ${body.component ?? "service"} · v${body.version ?? "unknown"}`,
      });
    } catch (error) {
      setHealth({
        status: "offline",
        detail: error instanceof Error ? error.message : "Health check failed",
      });
    }

    try {
      const response = await fetch("/ready", {
        cache: "no-store",
        credentials: "include",
      });
      const body = await response.json().catch(() => ({}));
      const checks = body.checks as Record<string, boolean> | undefined;
      const passed = checks ? Object.values(checks).filter(Boolean).length : 0;
      const total = checks ? Object.keys(checks).length : 0;
      const allReady = response.ok && body.status === "ready";
      setReadiness({
        status: allReady ? "online" : total > 0 ? "degraded" : "offline",
        detail: total > 0
          ? `${passed}/${total} readiness checks passed`
          : body.status ?? `Readiness endpoint returned ${response.status}`,
      });
    } catch (error) {
      setReadiness({
        status: "offline",
        detail: error instanceof Error ? error.message : "Readiness check failed",
      });
    }
    setCheckedAt(new Date().toLocaleTimeString());
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <main className="min-h-screen bg-black px-5 py-8 text-white md:px-8">
      <div className="mx-auto max-w-7xl space-y-8">
        <header className="flex flex-col justify-between gap-4 border-b border-white/10 pb-6 md:flex-row md:items-end">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.24em] text-cyan-400">
              AURAGENT · Platform control center
            </p>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight md:text-4xl">
              Autonomous Agent Infrastructure
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
              A single entry point for agent development, runtime, trust, tools,
              memory, isolation, evidence, operations and enterprise controls.
            </p>
          </div>
          <button
            type="button"
            onClick={() => void refresh()}
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-white/15 px-4 py-2 text-sm text-slate-200 transition hover:border-cyan-400/50 hover:text-white"
          >
            <RefreshCw className="h-4 w-4" />
            Refresh status
          </button>
        </header>

        <section aria-label="Platform health" className="grid gap-4 md:grid-cols-2">
          <div className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-sm font-medium">
                <Activity className="h-4 w-4 text-cyan-300" /> API health
              </div>
              <StatusPill value={health.status} />
            </div>
            <p className="mt-3 text-sm text-slate-400">{health.detail}</p>
          </div>
          <div className="rounded-xl border border-white/10 bg-white/[0.03] p-5">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-sm font-medium">
                <Database className="h-4 w-4 text-cyan-300" /> Service readiness
              </div>
              <StatusPill value={readiness.status} />
            </div>
            <p className="mt-3 text-sm text-slate-400">{readiness.detail}</p>
          </div>
        </section>

        <section>
          <div className="mb-4 flex items-end justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold">Platform modules</h2>
              <p className="mt-1 text-sm text-slate-500">
                Existing dashboard pages are linked directly; remaining modules expose their API surfaces and are being connected to dedicated workflows.
              </p>
            </div>
            {checkedAt && <p className="shrink-0 text-xs text-slate-600">Checked {checkedAt}</p>}
          </div>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {modules.map((module) => {
              const Icon = module.icon;
              const available = module.state === "Available";
              return (
                <Link
                  key={module.name}
                  href={module.href}
                  id={module.name.toLowerCase().replaceAll(" ", "-")}
                  className="group rounded-xl border border-white/10 bg-white/[0.025] p-4 transition hover:border-cyan-400/40 hover:bg-cyan-400/[0.04]"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="rounded-lg border border-cyan-400/20 bg-cyan-400/10 p-2 text-cyan-300">
                      <Icon className="h-5 w-5" />
                    </div>
                    <span className={`rounded-full border px-2 py-1 text-[10px] font-mono ${available ? "border-emerald-500/30 text-emerald-300" : "border-amber-500/30 text-amber-300"}`}>
                      {module.state}
                    </span>
                  </div>
                  <h3 className="mt-4 font-medium text-white group-hover:text-cyan-200">{module.name}</h3>
                  <p className="mt-2 min-h-10 text-sm leading-5 text-slate-400">{module.description}</p>
                  <div className="mt-4 flex items-center justify-between text-xs text-slate-500">
                    <span>{module.phase}</span>
                    <span className="text-cyan-300">Open module ↗</span>
                  </div>
                </Link>
              );
            })}
          </div>
        </section>

        <footer className="flex flex-col gap-2 border-t border-white/10 pt-5 text-xs text-slate-500 md:flex-row md:items-center md:justify-between">
          <span>AURAGENT · AgentShield security component</span>
          <span>API status is live; module labels describe current dashboard coverage, not completion certification.</span>
        </footer>
      </div>
    </main>
  );
}
