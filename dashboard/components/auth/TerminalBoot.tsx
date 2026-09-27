"use client";

import { useEffect, useState } from "react";
import { CheckCircle2, Loader2, Zap } from "lucide-react";

export type BootLine = {
  text: string;
  delay: number; // ms before printing
  status: "pending" | "ok" | "warn";
};

/**
 * Terminal-style boot animation.
 * Prints lines one at a time, with a spinner on the last pending line.
 * When done, the last line becomes "ok" and a success state appears.
 */
export function TerminalBoot({
  lines,
  done,
  onDone,
}: {
  lines: BootLine[];
  done: boolean;
  onDone?: () => void;
}) {
  const [visibleCount, setVisibleCount] = useState(0);

  useEffect(() => {
    if (visibleCount >= lines.length) {
      if (done && onDone) onDone();
      return;
    }
    const nextLine = lines[visibleCount];
    const t = setTimeout(() => {
      setVisibleCount((c) => c + 1);
    }, nextLine.delay);
    return () => clearTimeout(t);
  }, [visibleCount, lines, done, onDone]);

  return (
    <div className="relative bg-black/80 border border-emerald-500/20 p-5 font-mono text-[11px] leading-relaxed">
      {/* Terminal chrome */}
      <div className="flex items-center justify-between mb-3 pb-2 border-b border-emerald-500/10">
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-rose-500/60" />
          <span className="w-2.5 h-2.5 rounded-full bg-amber-500/60" />
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/60" />
        </div>
        <span className="text-[9px] tracking-[0.3em] text-slate-600 uppercase">
          agentshield · provisioning
        </span>
        <Zap className="w-3 h-3 text-emerald-400/60" />
      </div>

      {/* Log lines */}
      <div className="space-y-1 min-h-[200px]">
        {lines.slice(0, visibleCount).map((line, i) => {
          const isLast = i === visibleCount - 1;
          const isPending = isLast && line.status === "pending" && !done;
          return (
            <div key={i} className="flex items-start gap-2">
              {line.status === "ok" ? (
                <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0 mt-0.5" />
              ) : isPending ? (
                <Loader2 className="w-3 h-3 text-amber-400 animate-spin shrink-0 mt-0.5" />
              ) : (
                <span className="w-3 h-3 shrink-0 mt-0.5 text-amber-400">›</span>
              )}
              <span
                className={
                  line.status === "ok"
                    ? "text-slate-400"
                    : isPending
                    ? "text-amber-300"
                    : "text-slate-500"
                }
              >
                {line.text}
              </span>
            </div>
          );
        })}
        {visibleCount > 0 && (
          <div className="flex items-center gap-2 mt-2">
            <span className="text-emerald-400/70">$</span>
            <span className="w-1.5 h-3 bg-emerald-400 animate-pulse" />
          </div>
        )}
      </div>
    </div>
  );
}

export function buildSignupBootLines(tenantName: string): BootLine[] {
  return [
    { text: "bootstrapping agentshield runtime", delay: 100, status: "ok" },
    { text: "loading environment config", delay: 180, status: "ok" },
    { text: `registering tenant · ${tenantName.toLowerCase().slice(0, 24)}`, delay: 220, status: "ok" },
    { text: "connecting to postgres", delay: 260, status: "ok" },
    { text: "running schema migrations", delay: 300, status: "ok" },
    { text: "provisioning isolated workspace", delay: 280, status: "ok" },
    { text: "initializing argon2id hasher", delay: 200, status: "ok" },
    { text: "generating tenant hmac secret", delay: 220, status: "ok" },
    { text: "issuing first api key", delay: 240, status: "ok" },
    { text: "connecting to redis vault", delay: 200, status: "ok" },
    { text: "verifying audit chain integrity", delay: 220, status: "ok" },
    { text: "sealing workspace · zero-trust enforced", delay: 260, status: "ok" },
  ];
}