"use client";

import { useEffect, useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { Loader2, CheckCircle2, AlertCircle } from "lucide-react";

function VerifyEmailInner() {
  const params = useSearchParams();
  const token = params.get("token") ?? "";
  const [state, setState] = useState<"loading" | "ok" | "error">("loading");

  useEffect(() => {
    if (!token) {
      setState("error");
      return;
    }
    (async () => {
      try {
        const res = await fetch("/api/auth/verify-email", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token }),
          credentials: "include",
        });
        setState(res.ok ? "ok" : "error");
      } catch {
        setState("error");
      }
    })();
  }, [token]);

  if (state === "loading") {
    return (
      <div className="relative bg-black/80 backdrop-blur-2xl border border-cyan-400/20 p-7 flex items-center gap-3">
        <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />
        <span className="text-[11px] font-mono text-slate-400 tracking-wider">
          Verifying email…
        </span>
      </div>
    );
  }

  if (state === "ok") {
    return (
      <div className="relative bg-black/80 backdrop-blur-2xl border border-emerald-500/30 p-7">
        <div className="flex items-center gap-2 mb-3">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <h1 className="text-sm font-mono tracking-[0.28em] uppercase text-slate-300">
            Email verified
          </h1>
        </div>
        <p className="text-[11px] font-mono text-slate-500 leading-relaxed mb-5">
          Your account is fully activated. Audit exports, webhook
          notifications, and policy sync are now unlocked.
        </p>
        <Link
          href="/dashboard"
          className="text-[10px] font-mono tracking-widest uppercase text-emerald-400 hover:text-emerald-300"
        >
          Open dashboard →
        </Link>
      </div>
    );
  }

  return (
    <div className="relative bg-black/80 backdrop-blur-2xl border border-rose-500/30 p-7">
      <div className="flex items-center gap-2 mb-3">
        <AlertCircle className="w-4 h-4 text-rose-400" />
        <h1 className="text-sm font-mono tracking-[0.28em] uppercase text-slate-300">
          Verification failed
        </h1>
      </div>
      <p className="text-[11px] font-mono text-slate-500 leading-relaxed mb-5">
        This link is invalid or has expired. Request a new one from your
        dashboard.
      </p>
      <Link
        href="/dashboard"
        className="text-[10px] font-mono tracking-widest uppercase text-cyan-400 hover:text-cyan-300"
      >
        Go to dashboard →
      </Link>
    </div>
  );
}

export default function VerifyEmailPage() {
  return (
    <Suspense
      fallback={
        <div className="relative bg-black/80 backdrop-blur-2xl border border-cyan-400/20 p-7 h-[200px] flex items-center justify-center">
          <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />
        </div>
      }
    >
      <VerifyEmailInner />
    </Suspense>
  );
}