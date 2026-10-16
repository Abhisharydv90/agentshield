"use client";

import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/csrf";

type Agent = {
  agent_id: string;
  name: string;
  description: string;
  capabilities: string[];
  status: "active" | "suspended" | "revoked";
  created_at: string;
  last_seen_at: string | null;
};

type Version = {
  version_id: string;
  version: string;
  status: string;
  description: string;
  capabilities: string[];
  content_hash: string;
  created_at: string;
  published_at: string | null;
};

type Template = {
  template_id: string;
  name: string;
  description: string;
  version: string;
  capabilities: string[];
  active: boolean;
};

const CAPABILITIES = [
  "agent:invoke",
  "tool:read",
  "tool:write",
  "tool:delete",
  "tool:execute",
  "filesystem:read",
  "filesystem:write",
  "network:egress",
  "memory:read",
  "memory:write",
  "secret:use",
  "agent:delegate",
  "isolation:execute",
  "device:use",
];

async function readJson<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let detail = "";
    try {
      const body = await response.json();
      detail = typeof body?.detail === "string" ? body.detail : JSON.stringify(body);
    } catch {
      detail = await response.text().catch(() => "");
    }
    throw new Error(detail || `Request failed (${response.status})`);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export default function AgentsPage() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [templates, setTemplates] = useState<Template[]>([]);
  const [versions, setVersions] = useState<Record<string, Version[]>>({});
  const [selectedAgent, setSelectedAgent] = useState<string>("");
  const [tab, setTab] = useState<"agents" | "templates">("agents");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [capabilities, setCapabilities] = useState<string[]>(["agent:invoke"]);
  const [version, setVersion] = useState("1.0.0");
  const [runtime, setRuntime] = useState("python");
  const [entrypoint, setEntrypoint] = useState("agent.main:run");

  const [templateName, setTemplateName] = useState("");
  const [templateVersion, setTemplateVersion] = useState("1.0.0");

  const selected = useMemo(
    () => agents.find((agent) => agent.agent_id === selectedAgent) ?? null,
    [agents, selectedAgent],
  );

  async function load() {
    setMessage("");
    const [agentsResponse, templatesResponse] = await Promise.all([
      apiFetch("/v1/agents"),
      apiFetch("/v1/agents/templates"),
    ]);
    const [nextAgents, nextTemplates] = await Promise.all([
      readJson<Agent[]>(agentsResponse),
      readJson<Template[]>(templatesResponse),
    ]);
    setAgents(nextAgents);
    setTemplates(nextTemplates);
    if (!selectedAgent && nextAgents[0]) setSelectedAgent(nextAgents[0].agent_id);
  }

  useEffect(() => {
    load().catch((error) => setMessage(error instanceof Error ? error.message : "Unable to load agents"));
  }, []);

  async function loadVersions(agentId: string) {
    const response = await apiFetch(`/v1/agents/${agentId}/versions`);
    const rows = await readJson<Version[]>(response);
    setVersions((prev) => ({ ...prev, [agentId]: rows }));
  }

  useEffect(() => {
    if (!selectedAgent) return;
    loadVersions(selectedAgent).catch((error) =>
      setMessage(error instanceof Error ? error.message : "Unable to load versions"),
    );
  }, [selectedAgent]);

  function toggleCapability(capability: string) {
    setCapabilities((current) => {
      if (current.includes(capability)) {
        if (capability === "agent:invoke") return current;
        return current.filter((item) => item !== capability);
      }
      return [...current, capability];
    });
  }

  async function createAgent() {
    setBusy(true);
    setMessage("");
    try {
      const response = await apiFetch("/v1/agents", {
        method: "POST",
        body: JSON.stringify({
          name,
          description,
          capabilities,
          version,
          manifest: {
            runtime,
            entrypoint,
            tools: [],
          },
        }),
      });
      const created = await readJson<Agent>(response);
      setName("");
      setDescription("");
      setSelectedAgent(created.agent_id);
      await load();
      setMessage(`Agent ${created.name} created.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to create agent");
    } finally {
      setBusy(false);
    }
  }

  async function transition(status: Agent["status"]) {
    if (!selectedAgent) return;
    setBusy(true);
    try {
      await readJson(
        await apiFetch(`/v1/agents/${selectedAgent}/lifecycle`, {
          method: "POST",
          body: JSON.stringify({ status }),
        }),
      );
      await load();
      setMessage(`Agent lifecycle changed to ${status}.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Lifecycle operation failed");
    } finally {
      setBusy(false);
    }
  }

  async function createVersion() {
    if (!selectedAgent) return;
    setBusy(true);
    try {
      await readJson(
        await apiFetch(`/v1/agents/${selectedAgent}/versions`, {
          method: "POST",
          body: JSON.stringify({
            version,
            description,
            capabilities,
            manifest: {
              runtime,
              entrypoint,
              tools: [],
            },
          }),
        }),
      );
      await loadVersions(selectedAgent);
      setMessage(`Version ${version} created as draft.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Version creation failed");
    } finally {
      setBusy(false);
    }
  }

  async function publishVersion(versionId: string) {
    if (!selectedAgent) return;
    setBusy(true);
    try {
      await readJson(
        await apiFetch(`/v1/agents/${selectedAgent}/versions/${versionId}/publish`, {
          method: "POST",
        }),
      );
      await load();
      await loadVersions(selectedAgent);
      setMessage("Version published and capability set updated.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Publish failed");
    } finally {
      setBusy(false);
    }
  }

  async function createTemplate() {
    setBusy(true);
    try {
      await readJson(
        await apiFetch("/v1/agents/templates", {
          method: "POST",
          body: JSON.stringify({
            name: templateName,
            version: templateVersion,
            capabilities,
            manifest: { runtime, entrypoint, tools: [] },
          }),
        }),
      );
      setTemplateName("");
      await load();
      setMessage("Template created.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Template creation failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen bg-black text-white p-6 md:p-8">
      <div className="mx-auto max-w-7xl space-y-6">
        <header>
          <p className="text-xs font-mono uppercase tracking-[0.2em] text-emerald-400">AURAGENT · Phase 1</p>
          <div className="mt-2 flex flex-wrap items-end justify-between gap-4">
            <div>
              <h1 className="text-4xl font-semibold">Agent Development</h1>
              <p className="mt-2 text-sm text-slate-400">
                Build agents, version capability sets, manage lifecycle, and prepare deployments.
              </p>
            </div>
            <div className="flex gap-2">
              {(["agents", "templates"] as const).map((item) => (
                <button
                  key={item}
                  onClick={() => setTab(item)}
                  className={`border px-4 py-2 text-xs font-mono uppercase tracking-wider ${
                    tab === item
                      ? "border-emerald-400 bg-emerald-400/10 text-emerald-300"
                      : "border-slate-800 text-slate-500 hover:border-slate-600"
                  }`}
                >
                  {item}
                </button>
              ))}
            </div>
          </div>
        </header>

        {message && (
          <div className="border border-emerald-500/20 bg-emerald-500/5 px-4 py-3 text-sm text-emerald-300">
            {message}
          </div>
        )}

        {tab === "agents" ? (
          <div className="grid gap-6 lg:grid-cols-[360px_1fr]">
            <section className="border border-slate-800 bg-slate-950/60 p-5">
              <h2 className="text-lg font-semibold">Create agent</h2>
              <div className="mt-4 space-y-3">
                <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Agent name" className="w-full border border-slate-800 bg-black px-3 py-2 text-sm outline-none focus:border-emerald-500" />
                <textarea value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Description" rows={3} className="w-full border border-slate-800 bg-black px-3 py-2 text-sm outline-none focus:border-emerald-500" />
                <div className="grid grid-cols-2 gap-3">
                  <input value={version} onChange={(e) => setVersion(e.target.value)} placeholder="1.0.0" className="border border-slate-800 bg-black px-3 py-2 text-sm outline-none focus:border-emerald-500" />
                  <input value={runtime} onChange={(e) => setRuntime(e.target.value)} placeholder="python" className="border border-slate-800 bg-black px-3 py-2 text-sm outline-none focus:border-emerald-500" />
                </div>
                <input value={entrypoint} onChange={(e) => setEntrypoint(e.target.value)} placeholder="agent.main:run" className="w-full border border-slate-800 bg-black px-3 py-2 text-sm outline-none focus:border-emerald-500" />
                <div>
                  <p className="mb-2 text-[10px] font-mono uppercase tracking-wider text-slate-500">Capabilities</p>
                  <div className="grid grid-cols-2 gap-1.5">
                    {CAPABILITIES.map((capability) => (
                      <label key={capability} className="flex items-center gap-2 border border-slate-900 px-2 py-1.5 text-[10px] font-mono text-slate-400">
                        <input type="checkbox" checked={capabilities.includes(capability)} onChange={() => toggleCapability(capability)} />
                        <span className="truncate">{capability}</span>
                      </label>
                    ))}
                  </div>
                </div>
                <button
                  disabled={busy || !name.trim()}
                  onClick={createAgent}
                  className="w-full bg-emerald-400 px-4 py-2.5 text-sm font-semibold text-black disabled:opacity-40"
                >
                  Create agent
                </button>
              </div>
            </section>

            <section className="space-y-4">
              <div className="grid gap-3 sm:grid-cols-3">
                <Metric label="Agents" value={agents.length} />
                <Metric label="Active" value={agents.filter((a) => a.status === "active").length} />
                <Metric label="Templates" value={templates.length} />
              </div>

              <div className="grid gap-4 xl:grid-cols-[1fr_1fr]">
                <div className="space-y-2">
                  {agents.map((agent) => (
                    <button
                      key={agent.agent_id}
                      onClick={() => setSelectedAgent(agent.agent_id)}
                      className={`w-full border p-4 text-left transition ${
                        selectedAgent === agent.agent_id
                          ? "border-emerald-500/50 bg-emerald-500/5"
                          : "border-slate-800 bg-slate-950/40 hover:border-slate-700"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-4">
                        <div>
                          <div className="font-medium">{agent.name}</div>
                          <div className="mt-1 text-xs text-slate-500">{agent.description || "No description"}</div>
                        </div>
                        <Status value={agent.status} />
                      </div>
                      <div className="mt-3 flex flex-wrap gap-1">
                        {agent.capabilities.map((capability) => (
                          <span key={capability} className="border border-slate-800 px-1.5 py-0.5 text-[9px] font-mono text-slate-400">{capability}</span>
                        ))}
                      </div>
                    </button>
                  ))}
                  {!agents.length && <div className="border border-dashed border-slate-800 p-8 text-center text-sm text-slate-500">No agents yet.</div>}
                </div>

                <div className="border border-slate-800 bg-slate-950/60 p-5">
                  {selected ? (
                    <>
                      <div className="flex items-start justify-between gap-4">
                        <div>
                          <p className="text-xs font-mono uppercase tracking-wider text-emerald-400">Selected agent</p>
                          <h2 className="mt-1 text-2xl font-semibold">{selected.name}</h2>
                          <p className="mt-1 text-xs text-slate-500">{selected.agent_id}</p>
                        </div>
                        <div className="flex gap-2">
                          <button disabled={busy || selected.status === "revoked"} onClick={() => transition(selected.status === "active" ? "suspended" : "active")} className="border border-slate-700 px-3 py-2 text-xs">{selected.status === "active" ? "Suspend" : "Activate"}</button>
                          <button disabled={busy || selected.status === "revoked"} onClick={() => transition("revoked")} className="border border-rose-900/60 px-3 py-2 text-xs text-rose-300">Revoke</button>
                        </div>
                      </div>

                      <div className="mt-6">
                        <div className="flex items-center justify-between">
                          <h3 className="text-sm font-semibold">Version control</h3>
                          <button disabled={busy} onClick={createVersion} className="border border-emerald-500/40 px-3 py-2 text-xs text-emerald-300">New draft</button>
                        </div>
                        <div className="mt-3 space-y-2">
                          {(versions[selected.agent_id] ?? []).map((item) => (
                            <div key={item.version_id} className="border border-slate-800 p-3">
                              <div className="flex items-center justify-between gap-3">
                                <div>
                                  <span className="font-mono text-sm">{item.version}</span>
                                  <span className="ml-2 text-[10px] uppercase text-slate-500">{item.status}</span>
                                </div>
                                {item.status === "draft" && <button disabled={busy} onClick={() => publishVersion(item.version_id)} className="text-xs text-emerald-300">Publish</button>}
                              </div>
                              <p className="mt-1 text-xs text-slate-500">{item.description || "No description"}</p>
                              <p className="mt-2 truncate text-[10px] font-mono text-slate-600">{item.content_hash}</p>
                              <div className="mt-2 flex flex-wrap gap-1">
                                {item.capabilities.map((capability) => <span key={capability} className="border border-slate-900 px-1.5 py-0.5 text-[9px] text-slate-500">{capability}</span>)}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </>
                  ) : (
                    <div className="flex h-full items-center justify-center text-sm text-slate-500">Select an agent.</div>
                  )}
                </div>
              </div>
            </section>
          </div>
        ) : (
          <section className="grid gap-6 lg:grid-cols-[360px_1fr]">
            <div className="border border-slate-800 bg-slate-950/60 p-5">
              <h2 className="text-lg font-semibold">Create template</h2>
              <div className="mt-4 space-y-3">
                <input value={templateName} onChange={(e) => setTemplateName(e.target.value)} placeholder="Template name" className="w-full border border-slate-800 bg-black px-3 py-2 text-sm outline-none focus:border-emerald-500" />
                <input value={templateVersion} onChange={(e) => setTemplateVersion(e.target.value)} placeholder="1.0.0" className="w-full border border-slate-800 bg-black px-3 py-2 text-sm outline-none focus:border-emerald-500" />
                <button disabled={busy || !templateName.trim()} onClick={createTemplate} className="w-full bg-emerald-400 px-4 py-2.5 text-sm font-semibold text-black disabled:opacity-40">Create template</button>
                <p className="text-xs text-slate-500">Templates use the currently selected capability set and builder runtime.</p>
              </div>
            </div>
            <div className="space-y-3">
              {templates.map((template) => (
                <div key={template.template_id} className="border border-slate-800 bg-slate-950/60 p-5">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <h3 className="font-semibold">{template.name}</h3>
                      <p className="mt-1 text-xs text-slate-500">Version {template.version}</p>
                    </div>
                    <span className="text-[10px] font-mono uppercase text-emerald-400">active</span>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-1">
                    {template.capabilities.map((capability) => <span key={capability} className="border border-slate-900 px-1.5 py-0.5 text-[9px] text-slate-500">{capability}</span>)}
                  </div>
                </div>
              ))}
              {!templates.length && <div className="border border-dashed border-slate-800 p-8 text-center text-sm text-slate-500">No templates yet.</div>}
            </div>
          </section>
        )}
      </div>
    </main>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="border border-slate-800 bg-slate-950/60 p-4">
      <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500">{label}</div>
      <div className="mt-2 text-2xl font-semibold">{value}</div>
    </div>
  );
}

function Status({ value }: { value: string }) {
  return (
    <span className={`border px-2 py-1 text-[10px] font-mono uppercase ${
      value === "active"
        ? "border-emerald-500/30 text-emerald-300"
        : value === "suspended"
          ? "border-amber-500/30 text-amber-300"
          : "border-rose-500/30 text-rose-300"
    }`}>
      {value}
    </span>
  );
}
