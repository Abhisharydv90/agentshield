"use client";

import { useState, type FormEvent } from "react";
import Link from "next/link";
import { Mail, ArrowLeft, Loader2, CheckCircle2 } from "lucide-react";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);
  const [focused, setFocused] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!email.trim()) return;
    setLoading(true);
    try {
      await fetch("/api/auth/forgot-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim() }),
        credentials: "include",
      });
    } catch {
      /* always show success — never leak account existence */
    }
    setSent(true);
    setLoading(false);
  }

  return (
    <div className="relative bg-black/80 backdrop-blur-2xl border border-cyan-400/20 p-7">
      <span className="absolute top-0 left-0 w-2.5 h-2.5 border-l border-t border-cyan-400/40" />
      <span className="absolute top-0 right-0 w-2.5 h-2.5 border-r border-t border-cyan-400/40" />
      <span className="absolute bottom-0 left-0 w-2.5 h-2.5 border-l border-b border-cyan-400/40" />
      <span className="absolute bottom-0 right-0 w-2.5 h-2.5 border-r border-b border-cyan-400/40" />

      {sent ? (
        <>
          <div className="flex items-center gap-2 mb-3">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <h1 className="text-sm font-mono tracking-[0.28em] uppercase text-slate-300">
              Check your inbox
            </h1>
          </div>
          <p className="text-[11px] font-mono text-slate-500 leading-relaxed mb-6">
            If an account exists for{" "}
            <span className="text-cyan-400">{email}</span>, a reset link is on
            its way. The link expires in 30 minutes.
          </p>
          <Link
            href="/login"
            className="text-[10px] font-mono tracking-widest uppercase text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5"
          >
            <ArrowLeft className="w-3 h-3" />
            Back to sign in
          </Link>
        </>
      ) : (
        <>
          <div className="flex items-center gap-2 mb-1">
            <Mail className="w-4 h-4 text-cyan-400" />
            <h1 className="text-sm font-mono tracking-[0.28em] uppercase text-slate-300">
              Reset password
            </h1>
          </div>
          <p className="text-[10px] font-mono text-slate-600 mb-6 leading-relaxed">
            Enter your email and we'll send a reset link
          </p>

          <form onSubmit={submit} className="space-y-4">
            <div>
              <label className="flex items-center gap-1.5 text-[9px] font-mono tracking-[0.28em] text-slate-500 uppercase mb-1.5">
                <span className="text-cyan-500/60">
                  <Mail className="w-3 h-3" />
                </span>
                Email
              </label>
              <input
                type="email"
                autoFocus
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                onFocus={() => setFocused(true)}
                onBlur={() => setFocused(false)}
                placeholder="you@company.com"
                className={`w-full bg-black/60 border px-3 py-2.5 text-[12px] font-mono text-slate-200 placeholder:text-slate-700 focus:outline-none transition-all ${
                  focused
                    ? "border-cyan-400/70 shadow-[0_0_0_4px_rgba(34,211,238,0.12)]"
                    : "border-cyan-400/20"
                }`}
              />
            </div>

            <button
              type="submit"
              disabled={loading || !email.trim()}
              className="w-full bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-400/50 text-cyan-300 py-2.5 text-[11px] font-mono tracking-[0.25em] uppercase transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {loading ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Mail className="w-3.5 h-3.5" />
              )}
              {loading ? "Sending…" : "Send reset link"}
            </button>
          </form>

          <div className="mt-6 pt-5 border-t border-cyan-400/10 text-center text-[10px] font-mono tracking-wider text-slate-500">
            <Link
              href="/login"
              className="text-cyan-400 hover:text-cyan-300 transition-colors"
            >
              ← Back to sign in
            </Link>
          </div>
        </>
      )}
    </div>
  );
}