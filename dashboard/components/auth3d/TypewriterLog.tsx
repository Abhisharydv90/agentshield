"use client";

import { useEffect, useRef } from "react";

/**
 * Terminal that appends lines from a list, one at a time,
 * with a scanning typewriter effect. Auto-scrolls.
 */
export function TypewriterLog({ lines }: { lines: string[] }) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = containerRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines]);

  return (
    <div
      ref={containerRef}
      className="h-full overflow-y-auto pr-1 space-y-0.5 font-mono text-[10px] leading-relaxed"
    >
      {lines.length === 0 && (
        <div className="text-slate-700 italic">awaiting credentials…</div>
      )}
      {lines.map((line, i) => {
        const isHeader = line.startsWith("▸");
        const isSuccess = line.startsWith("✓");
        const isError = line.startsWith("✗");
        const isMono = line.startsWith("  ");
        return (
          <div
            key={i}
            className={
              isHeader
                ? "text-emerald-400"
                : isSuccess
                ? "text-emerald-300 font-semibold"
                : isError
                ? "text-rose-400"
                : isMono
                ? "text-slate-500 break-all"
                : "text-slate-400"
            }
            style={{
              animation: "logLine 0.35s ease-out",
            }}
          >
            {line}
          </div>
        );
      })}
    </div>
  );
}