"use client";

import { useState } from "react";
import { Activity, Ban, Play, RefreshCw } from "lucide-react";
import { apiFetch } from "@/lib/csrf";

type RuntimeTask = {
  task_id: string;
  tenant_id: string;
  agent_id: string;
  trace_id: string;
  kind: string;
  status: string;
  priority: number;
  attempt_count: number;
  max_attempts: number;
  timeout_seconds: number;
  payload_hash: string;
  result_hash: string | null;
  last_error_code: string | null;
};

async function readResponse<T>(response: Response): Promise<T> {
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    const detail =
      body && typeof body.detail === "string"
        ? body.detail
        : `Runtime request failed (${response.status})`;
    throw new Error(detail);
  }
  return body as T;
}

export default function RuntimePage() {
  const [kind, setKind] = useState("agent.task");
  const [payloadText, setPayloadText] = useState('{"input":"Describe the task to execute"}');
  const [priority, setPriority] = useState(0);
  const [timeoutSeconds, setTimeoutSeconds] = useState(300);
  const [taskId, setTaskId] = useState("");
  const [task, setTask] = useState<RuntimeTask | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [sessionId, setSessionId] = useState("");
  const [sessionBusy, setSessionBusy] = useState(false);

  async function submitTask() {
    let payload: unknown;
    try {
      payload = JSON.parse(payloadText);
    } catch {
      setMessage("Payload must be valid JSON.");
      return;
    }

    setBusy(true);
    setMessage("");
    try {
      const created = await readResponse<RuntimeTask>(
        await apiFetch("/api/runtime/tasks", {
          method: "POST",
          body: JSON.stringify({
            kind,
            payload,
            priority,
            timeout_seconds: timeoutSeconds,
            max_attempts: 3,
          }),
        }),
      );
      setTask(created);
      setTaskId(created.task_id);
      setMessage("Task accepted by the runtime control API.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Task submission failed.");
    } finally {
      setBusy(false);
    }
  }

  async function inspectTask() {
    const id = taskId.trim();
    if (!id) {
      setMessage("Enter a task ID first.");
      return;
    }
    setBusy(true);
    setMessage("");
    try {
      const result = await readResponse<RuntimeTask>(
        await apiFetch(`/api/runtime/tasks/${encodeURIComponent(id)}`),
      );
      setTask(result);
      setMessage("Latest task state loaded.");
    } catch (error) {
      setTask(null);
      setMessage(error instanceof Error ? error.message : "Unable to load task.");
    } finally {
      setBusy(false);
    }
  }

  async function cancelTask() {
    if (!task) return;
    setBusy(true);
    setMessage("");
    try {
      await readResponse<{ status: string; task_id: string }>(
        await apiFetch(`/api/runtime/tasks/${encodeURIComponent(task.task_id)}/cancel`, {
          method: "POST",
        }),
      );
      await inspectTask();
      setMessage("Cancellation request accepted.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to cancel task.");
    } finally {
      setBusy(false);
    }
  }

  async function createSession() {
    setSessionBusy(true);
    setMessage("");
    try {
      const result = await readResponse<{ session_id: string; trace_id: string }>(
        await apiFetch("/api/runtime/sessions", { method: "POST" }),
      );
      setSessionId(result.session_id);
      setMessage(`Runtime session created. Trace: ${result.trace_id}`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to create runtime session.");
    } finally {
      setSessionBusy(false);
    }
  }

  async function closeSession() {
    const id = sessionId.trim();
    if (!id) return;
    setSessionBusy(true);
    setMessage("");
    try {
      await readResponse<{ status: string; session_id: string }>(
        await apiFetch(`/api/runtime/sessions/${encodeURIComponent(id)}/close`, {
          method: "POST",
        }),
      );
      setSessionId("");
      setMessage("Runtime session closed.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to close runtime session.");
    } finally {
      setSessionBusy(false);
    }
  }

  return (
    <main className="min-h-screen bg-black px-5 py-8 text-white md:px-8">
      <div className="mx-auto max-w-6xl space-y-7">
        <header>
          <p className="font-mono text-xs uppercase tracking-[0.22em] text-cyan-400">
            AURAGENT · Runtime & orchestration
          </p>
          <h1 className="mt-2 text-3xl font-semibold md:text-4xl">Runtime tasks</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
            Submit, inspect and cancel tasks through the authenticated runtime API.
            The API enforces the current tenant, active agent identity and
            AGENT_INVOKE capability. This page does not simulate task execution.
          </p>
        </header>

        {message && (
          <div role="status" className="border border-cyan-500/20 bg-cyan-500/5 px-4 py-3 text-sm text-cyan-200">
            {message}
          </div>
        )}

        <section className="grid gap-5 lg:grid-cols-[1.1fr_0.9fr]">
          <div className="space-y-4 rounded-xl border border-white/10 bg-white/[0.025] p-5">
            <div className="flex items-center gap-2">
              <Play className="h-4 w-4 text-cyan-300" />
              <h2 className="font-semibold">Submit a runtime task</h2>
            </div>
            <label className="block space-y-2 text-sm">
              <span className="text-slate-400">Task kind</span>
              <input
                value={kind}
                onChange={(event) => setKind(event.target.value)}
                maxLength={160}
                className="w-full rounded-lg border border-white/10 bg-black px-3 py-2 outline-none focus:border-cyan-400"
              />
            </label>
            <label className="block space-y-2 text-sm">
              <span className="text-slate-400">JSON payload</span>
              <textarea
                value={payloadText}
                onChange={(event) => setPayloadText(event.target.value)}
                rows={8}
                spellCheck={false}
                className="w-full rounded-lg border border-white/10 bg-black px-3 py-3 font-mono text-xs leading-5 outline-none focus:border-cyan-400"
              />
            </label>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="space-y-2 text-sm">
                <span className="text-slate-400">Priority</span>
                <input
                  type="number"
                  value={priority}
                  onChange={(event) => setPriority(Number(event.target.value))}
                  className="w-full rounded-lg border border-white/10 bg-black px-3 py-2"
                />
              </label>
              <label className="space-y-2 text-sm">
                <span className="text-slate-400">Timeout (seconds)</span>
                <input
                  type="number"
                  min={1}
                  max={86400}
                  value={timeoutSeconds}
                  onChange={(event) => setTimeoutSeconds(Number(event.target.value))}
                  className="w-full rounded-lg border border-white/10 bg-black px-3 py-2"
                />
              </label>
            </div>
            <button
              type="button"
              disabled={busy || !kind.trim() || timeoutSeconds < 1 || timeoutSeconds > 86400}
              onClick={() => void submitTask()}
              className="inline-flex items-center gap-2 rounded-lg bg-cyan-400 px-4 py-2.5 text-sm font-semibold text-black disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Play className="h-4 w-4" /> Submit task
            </button>
          </div>

          <div className="space-y-4 rounded-xl border border-white/10 bg-white/[0.025] p-5">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyan-300" />
              <h2 className="font-semibold">Inspect a task</h2>
            </div>
            <label className="block space-y-2 text-sm">
              <span className="text-slate-400">Task ID</span>
              <input
                value={taskId}
                onChange={(event) => setTaskId(event.target.value)}
                placeholder="UUID returned by task submission"
                className="w-full rounded-lg border border-white/10 bg-black px-3 py-2 font-mono text-xs"
              />
            </label>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                disabled={busy || !taskId.trim()}
                onClick={() => void inspectTask()}
                className="inline-flex items-center gap-2 rounded-lg border border-white/15 px-3 py-2 text-sm disabled:opacity-40"
              >
                <RefreshCw className="h-4 w-4" /> Refresh status
              </button>
              <button
                type="button"
                disabled={busy || !task || ["succeeded", "failed", "cancelled"].includes(task.status)}
                onClick={() => void cancelTask()}
                className="inline-flex items-center gap-2 rounded-lg border border-rose-500/30 px-3 py-2 text-sm text-rose-300 disabled:opacity-40"
              >
                <Ban className="h-4 w-4" /> Cancel task
              </button>
            </div>

            {task ? (
              <dl className="grid grid-cols-2 gap-3 rounded-lg border border-white/10 bg-black/50 p-4 text-xs">
                <div className="col-span-2">
                  <dt className="text-slate-500">Task ID</dt>
                  <dd className="mt-1 break-all font-mono text-slate-200">{task.task_id}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Status</dt>
                  <dd className="mt-1 font-semibold capitalize text-cyan-200">{task.status}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Kind</dt>
                  <dd className="mt-1 break-words text-slate-200">{task.kind}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Attempts</dt>
                  <dd className="mt-1 text-slate-200">{task.attempt_count}/{task.max_attempts}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Timeout</dt>
                  <dd className="mt-1 text-slate-200">{task.timeout_seconds}s</dd>
                </div>
                <div className="col-span-2">
                  <dt className="text-slate-500">Trace ID</dt>
                  <dd className="mt-1 break-all font-mono text-slate-200">{task.trace_id}</dd>
                </div>
                {task.last_error_code && (
                  <div className="col-span-2">
                    <dt className="text-slate-500">Last error code</dt>
                    <dd className="mt-1 text-rose-300">{task.last_error_code}</dd>
                  </div>
                )}
              </dl>
            ) : (
              <p className="rounded-lg border border-dashed border-white/10 p-6 text-sm text-slate-500">
                Submit a task or enter an existing task ID to inspect its current state.
              </p>
            )}
          </div>
        </section>
        <section className="rounded-xl border border-white/10 bg-white/[0.025] p-5">
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-cyan-300" />
            <h2 className="font-semibold">Runtime session lifecycle</h2>
          </div>
          <p className="mt-2 text-sm text-slate-400">
            Create a session for the authenticated agent, then close it when its work is complete.
            Session identifiers are scoped and ownership-checked by the backend.
          </p>
          {sessionId && (
            <p className="mt-4 break-all rounded-lg border border-white/10 bg-black/50 p-3 font-mono text-xs text-slate-200">
              {sessionId}
            </p>
          )}
          <div className="mt-4 flex flex-wrap gap-2">
            <button
              type="button"
              disabled={sessionBusy || Boolean(sessionId)}
              onClick={() => void createSession()}
              className="rounded-lg bg-cyan-400 px-4 py-2 text-sm font-semibold text-black disabled:opacity-40"
            >
              Create session
            </button>
            <button
              type="button"
              disabled={sessionBusy || !sessionId}
              onClick={() => void closeSession()}
              className="rounded-lg border border-rose-500/30 px-4 py-2 text-sm text-rose-300 disabled:opacity-40"
            >
              Close session
            </button>
          </div>
        </section>

        <p className="text-xs leading-5 text-slate-500">
          Task submission requires a valid authenticated agent with the runtime
          invocation capability. A task may be accepted but not execute if no
          compatible worker or handler is available. Session creation and closure
          are also authenticated runtime operations; this UI does not fabricate
          session state.
        </p>
      </div>
    </main>
  );
}
