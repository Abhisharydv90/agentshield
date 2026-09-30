"use client";

import { useState, Suspense, type FormEvent } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { Lock, Loader2, CheckCircle2, AlertCircle } from "lucide-react";

function ResetPasswordInner() {
  const router = useRouter();
  const params = useSearchParams();
  const token = params.get("token") ?? "";

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);

    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    if (!/[a-zA-Z]/.test(password) || !/\d/.test(password)) {
      setError("Password must contain a letter and a digit.");
      return;
    }
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("/api/auth/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, new_password: password }),
        credentials: "include",
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        const detail = data?.detail;
        throw new Error(
          detail === "invalid_or_expired_token"
            ? "This reset link is invalid or has expired. Request a new one."
            : typeof detail === "string"
              ? detail
              : "Reset failed."
        );
      }

      setDone(true);
      setTimeout(() => router.push("/login"), 2500);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Reset failed.");
    } finally {
      setLoading(false);
    }
  }

  if (!token) {
    return (
      <div className="relative bg-black/80 backdrop-blur-2xl border border-rose-500/30 p-7">
        <div className="flex items-center gap-2 mb-3">
          <AlertCircle className="w-4 h-4 text-rose-400" />
          <h1 className="text-sm font-mono tracking-[0.28em] uppercase text-slate-300">
            Invalid link
          </h1>
        </div>
        <p className="text-[11px] font-mono text-slate-500 mb-4">
          This password reset URL is missing its token. Request a new link.
        </p>
        <Link
          href="/forgot-password"
          className="text-[10px] font-mono tracking-widest uppercase text-cyan-400 hover:text-cyan-300"
        >
          Request new link →
        </Link>
      </div>
    );
  }

  if (done) {
    return (
      <div className="relative bg-black/80 backdrop-blur-2xl border border-emerald-500/30 p-7">
        <div className="flex items-center gap-2 mb-3">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <h1 className="text-sm font-mono tracking-[0.28em] uppercase text-slate-300">
            Password updated
          </h1>
        </div>
        <p className="text-[11px] font-mono text-slate-500 mb-4">
          Your password has been reset. Redirecting to sign in…
        </p>
      </div>
    );
  }

  return (
    <div className="relative bg-black/80 backdrop-blur-2xl border border-cyan-400/20 p-7">
      <span className="absolute top-0 left-0 w-2.5 h-2.5 border-l border-t border-cyan-400/40" />
      <span className="absolute top-0 right-0 w-2.5 h-2.5 border-r border-t border-cyan-400/40" />
      <span className="absolute bottom-0 left-0 w-2.5 h-2.5 border-l border-b border-cyan-400/40" />
      <span className="absolute bottom-0 right-0 w-2.5 h-2.5 border-r border-b border-cyan-400/40" />

      <div className="flex items-center gap-2 mb-1">
        <Lock className="w-4 h-4 text-cyan-400" />
        <h1 className="text-sm font-mono tracking-[0.28em] uppercase text-slate-300">
          Choose new password
        </h1>
      </div>
      <p className="text-[10px] font-mono text-slate-600 mb-6 leading-relaxed">
        Minimum 8 characters · at least one letter and one digit
      </p>

      <form onSubmit={submit} className="space-y-4">
        <div>
          <label className="text-[9px] font-mono tracking-[0.28em] text-slate-500 uppercase mb-1.5 block">
            New password
          </label>
          <input
            type="password"
            autoFocus
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••"
            autoComplete="new-password"
            className="w-full bg-black/60 border border-cyan-400/20 px-3 py-2.5 text-[12px] font-mono text-slate-200 placeholder:text-slate-700 focus:outline-none focus:border-cyan-400/70 transition-all"
          />
        </div>
        <div>
          <label className="text-[9px] font-mono tracking-[0.28em] text-slate-500 uppercase mb-1.5 block">
            Confirm password
          </label>
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder="••••••••"
            autoComplete="new-password"
            className="w-full bg-black/60 border border-cyan-400/20 px-3 py-2.5 text-[12px] font-mono text-slate-200 placeholder:text-slate-700 focus:outline-none focus:border-cyan-400/70 transition-all"
          />
        </div>

        {error && (
          <div className="flex items-start gap-2 bg-rose-500/10 border border-rose-500/30 px-3 py-2 text-[11px] font-mono text-rose-300">
            <AlertCircle className="w-3.5 h-3.5 shrink-0 mt-px" />
            <span>{error}</span>
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-400/50 text-cyan-300 py-2.5 text-[11px] font-mono tracking-[0.25em] uppercase transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
        >
          {loading ? (
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
          ) : (
            <Lock className="w-3.5 h-3.5" />
          )}
          {loading ? "Updating…" : "Update password"}
        </button>
      </form>
    </div>
  );
}

export default function ResetPasswordPage() {
  return (
    <Suspense
      fallback={
        <div className="relative bg-black/80 backdrop-blur-2xl border border-cyan-400/20 p-7 h-[300px] flex items-center justify-center">
          <div className="w-4 h-4 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
        </div>
      }
    >
      <ResetPasswordInner />
    </Suspense>
  );
}