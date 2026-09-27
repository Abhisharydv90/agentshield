"use client";

import { useEffect, useState } from "react";

/**
 * Animates a hex hash character by character with staggered reveal.
 * Optional progress bar above.
 */
export function HashReveal({
  hash,
  label,
  progress = 1,
}: {
  hash: string;
  label: string;
  progress?: number;
}) {
  const [shown, setShown] = useState(0);

  useEffect(() => {
    setShown(0);
    let i = 0;
    const timer = setInterval(() => {
      i += Math.max(1, Math.floor(hash.length / 24));
      setShown(Math.min(i, hash.length));
      if (i >= hash.length) clearInterval(timer);
    }, 28);
    return () => clearInterval(timer);
  }, [hash]);

  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-2 text-[9px] font-mono tracking-widest text-slate-500 uppercase">
        <span className="w-1 h-1 rounded-full bg-amber-400 animate-pulse" />
        {label}
      </div>
      <div className="relative h-[2px] bg-slate-800/80 overflow-hidden">
        <div
          className="absolute inset-y-0 left-0 bg-amber-400 transition-all duration-500"
          style={{ width: `${Math.round(progress * 100)}%`, boxShadow: "0 0 8px #f59e0b" }}
        />
      </div>
      <div className="font-mono text-[10px] text-amber-300/90 break-all leading-relaxed">
        {hash.slice(0, shown)}
        {shown < hash.length && (
          <span className="inline-block w-1 h-3 bg-amber-400 animate-pulse ml-0.5 align-middle" />
        )}
      </div>
    </div>
  );
}