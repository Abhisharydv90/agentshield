"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/csrf";

type Agent = { agent_id: string; name: string; status: string };
type Version = { version_id: string; version: string; status: string; content_hash: string };
type Deployment = {
  deployment_id: string;
  agent_id: string;
  version_id: string;
  environment: string;
  region: string;
  desired_replicas: number;
  status: string;
  created_at: string;
};

async function readJson<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let message = "";
    try {
      const body = await response.json();
      message = typeof body?.detail === "string" ? body.detail : JSON.stringify(body);
    } catch {
      message = await response.text().catch(() => "");
    }
    throw new Error(message || `Request failed (${response.status})`);
  }
  return response.status === 204 ? (undefined as T) : response.json() as Promise<T>;
}

export default function DeploymentsPage() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [versions, setVersions] = useState<Version[]>([]);
  const [deployments, setDeployments] = useState<Deployment[]>([]);
  const [agentId, setAgentId] = useState("");
  const [versionId, setVersionId] = useState("");
  const [environment, setEnvironment] = useState("development");
  const [region, setRegion] = useState("local");
  const [replicas, setReplicas] = useState(1);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  async function loadAgentsAndDeployments() {
    const [a, d] = await Promise.all([
      apiFetch("/v1/agents"),
      apiFetch("/v1/deployments"),
    ]);
    const nextAgents = await readJson<Agent[]>(a);
    setAgents(nextAgents);
    setDeployments(await readJson<Deployment[]>(d));
    if (!agentId && nextAgents[0]) setAgentId(nextAgents[0].agent_id);
  }

  async function loadVersions(id: string) {
    const response = await apiFetch(`/v1/agents/${id}/versions`);
    const next = await readJson<Version[]>(response);
    setVersions(next);
    const published = next.find((item) => item.status === "published");
    setVersionId(published?.version_id ?? "");
  }

  useEffect(() => {
    loadAgentsAndDeployments().catch((error) =>
      setMessage(error instanceof Error ? error.message : "Unable to load deployments"),
    );
  }, []);

  useEffect(() => {
    if (agentId) loadVersions(agentId).catch((error) =>
      setMessage(error instanceof Error ? error.message : "Unable to load agent versions"),
    );
  }, [agentId]);

  async function createDeployment() {
    if (!agentId || !versionId) return;
    setBusy(true);
    setMessage("");
    try {
      await readJson(
        await apiFetch("/v1/deployments", {
          method: "POST",
          body: JSON.stringify({
            agent_id: agentId,
            version_id: versionId,
            environment,
            region,
            desired_replicas: replicas,
            config: {},
          }),
        }),
      );
      await loadAgentsAndDeployments();
      setMessage("Deployment declaration created.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Deployment creation failed");
    } finally {
      setBusy(false);
    }
  }

  async function stopDeployment(id: string) {
    setBusy(true);
    try {
      await readJson(
        await apiFetch(`/v1/deployments/${id}/stop`, { method: "POST" }),
      );
      await loadAgentsAndDeployments();
      setMessage("Deployment stopped.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to stop deployment");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen bg-black text-white p-6 md:p-8">
      <div className="mx-auto max-w-6xl space-y-6">
        <header>
          <p className="text-xs font-mono uppercase tracking-[0.2em] text-cyan-400">AURAGENT · Phase 1</p>
          <h1 className="mt-2 text-4xl font-semibold">Deployments</h1>
          <p className="mt-2 text-sm text-slate-400">
            Declare where an immutable agent version should run. Execution is owned by Runtime and Isolation.
          </p>
        </header>

        {message && (
          <div className="border border-cyan-500/20 bg-cyan-500/5 px-4 py-3 text-sm text-cyan-300">{message}</div>
        )}

        <section className="border border-slate-800 bg-slate-950/60 p-5">
          <h2 className="text-lg font-semibold">New deployment</h2>
          <div className="mt-4 grid gap-3 md:grid-cols-2 lg:grid-cols-5">
            <select value={agentId} onChange={(e) => setAgentId(e.target.value)} className="border border-slate-800 bg-black px-3 py-2 text-sm">
              <option value="">Select agent</option>
              {agents.map((agent) => <option key={agent.agent_id} value={agent.agent_id}>{agent.name}</option>)}
            </select>
            <select value={versionId} onChange={(e) => setVersionId(e.target.value)} className="border border-slate-800 bg-black px-3 py-2 text-sm">
              <option value="">Published version</option>
              {versions.filter((v) => v.status === "published").map((item) => (
                <option key={item.version_id} value={item.version_id}>{item.version}</option>
              ))}
            </select>
            <input value={environment} onChange={(e) => setEnvironment(e.target.value)} placeholder="environment" className="border border-slate-800 bg-black px-3 py-2 text-sm" />
            <input value={region} onChange={(e) => setRegion(e.target.value)} placeholder="region" className="border border-slate-800 bg-black px-3 py-2 text-sm" />
            <div className="flex gap-2">
              <input type="number" min={1} max={100} value={replicas} onChange={(e) => setReplicas(Number(e.target.value))} className="w-20 border border-slate-800 bg-black px-3 py-2 text-sm" />
              <button disabled={busy || !versionId} onClick={createDeployment} className="flex-1 bg-cyan-400 px-4 py-2 text-sm font-semibold text-black disabled:opacity-40">Deploy</button>
            </div>
          </div>
        </section>

        <section className="space-y-3">
          {deployments.map((deployment) => {
            const agent = agents.find((a) => a.agent_id === deployment.agent_id);
            const version = versions.find((v) => v.version_id === deployment.version_id);
            return (
              <div key={deployment.deployment_id} className="border border-slate-800 bg-slate-950/50 p-5">
                <div className="flex flex-wrap items-center justify-between gap-4">
                  <div>
                    <h3 className="font-semibold">{agent?.name ?? deployment.agent_id}</h3>
                    <p className="mt-1 text-xs font-mono text-slate-500">
                      v{version?.version ?? deployment.version_id} · {deployment.environment} · {deployment.region}
                    </p>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono uppercase text-emerald-300">{deployment.status}</span>
                    {deployment.status === "active" && (
                      <button disabled={busy} onClick={() => stopDeployment(deployment.deployment_id)} className="border border-rose-900/60 px-3 py-2 text-xs text-rose-300">Stop</button>
                    )}
                  </div>
                </div>
                <div className="mt-3 text-xs text-slate-500">
                  Replicas requested: <span className="text-slate-300">{deployment.desired_replicas}</span>
                  <span className="mx-2">·</span>
                  Declared: {new Date(deployment.created_at).toLocaleString()}
                </div>
              </div>
            );
          })}
          {!deployments.length && (
            <div className="border border-dashed border-slate-800 p-10 text-center text-sm text-slate-500">
              No deployment declarations yet.
            </div>
          )}
        </section>
      </div>
    </main>
  );
}
