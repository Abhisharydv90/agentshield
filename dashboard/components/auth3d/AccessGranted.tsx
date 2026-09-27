"use client";

import { useEffect, useState } from "react";
import { useAuthTransition } from "./context";

/**
 * Scanline overlay that sweeps down the screen during the warp phase.
 * Fades in "ACCESS GRANTED" and then disappears.
 */
export function AccessGranted() {
  const { phase } = useAuthTransition();
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (phase === "warp") {
      setVisible(true);
      const t = setTimeout(() => setVisible(false), 2400);
      return () => clearTimeout(t);
    }
  }, [phase]);

  if (!visible) return null;

  return (
    <div className="fixed inset-0 pointer-events-none z-[60]">
      {/* Scan line */}
      <div
        className="absolute left-0 right-0 h-[2px] animate-[scanLine_2.4s_ease-out_forwards]"
        style={{
          background:
            "linear-gradient(90deg, transparent, #34d399 15%, #34d399 85%, transparent)",
          boxShadow: "0 0 32px rgba(52,211,153,0.9)",
        }}
      />
      {/* Text */}
      <div className="absolute inset-x-0 top-1/2 -translate-y-1/2 flex items-center justify-center">
        <div className="animate-[fadeScale_2.2s_ease-out_forwards]">
          <div
            className="font-mono text-3xl md:text-5xl font-black tracking-[0.3em] text-emerald-400"
            style={{ textShadow: "0 0 40px rgba(52,211,153,0.9)" }}
          >
            ACCESS GRANTED
          </div>
          <div className="text-center mt-3 text-[10px] font-mono tracking-[0.5em] text-emerald-500/70 uppercase">
            entering secure workspace
          </div>
        </div>
      </div>
      {/* Vignette darken */}
      <div className="absolute inset-0 bg-black/20" />
    </div>
  );
}