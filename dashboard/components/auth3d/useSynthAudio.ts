"use client";

import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Web Audio synth. No external files. Sounds are generated live.
 * Default: muted. User can unmute via toggle.
 */
export function useSynthAudio() {
  const [muted, setMuted] = useState(true);
  const ctxRef = useRef<AudioContext | null>(null);

  const ensureCtx = useCallback(() => {
    if (typeof window === "undefined") return null;
    if (!ctxRef.current) {
      const AC = window.AudioContext || (window as any).webkitAudioContext;
      if (!AC) return null;
      ctxRef.current = new AC();
    }
    if (ctxRef.current.state === "suspended") {
      ctxRef.current.resume();
    }
    return ctxRef.current;
  }, []);

  const playTone = useCallback(
    (freq: number, duration = 0.15, gain = 0.06, type: OscillatorType = "sine") => {
      if (muted) return;
      const ctx = ensureCtx();
      if (!ctx) return;
      const osc = ctx.createOscillator();
      const g = ctx.createGain();
      osc.type = type;
      osc.frequency.setValueAtTime(freq, ctx.currentTime);
      g.gain.setValueAtTime(0, ctx.currentTime);
      g.gain.linearRampToValueAtTime(gain, ctx.currentTime + 0.01);
      g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + duration);
      osc.connect(g);
      g.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + duration);
    },
    [muted, ensureCtx]
  );

  const click = useCallback(() => playTone(880, 0.06, 0.03, "square"), [playTone]);
  const success = useCallback(() => {
    playTone(660, 0.12, 0.05, "sine");
    setTimeout(() => playTone(880, 0.12, 0.05, "sine"), 80);
    setTimeout(() => playTone(1320, 0.2, 0.05, "sine"), 160);
  }, [playTone]);
  const warp = useCallback(() => {
    playTone(120, 1.6, 0.04, "sawtooth");
    setTimeout(() => playTone(240, 0.8, 0.03, "sine"), 200);
  }, [playTone]);
  const error = useCallback(() => playTone(220, 0.18, 0.04, "square"), [playTone]);

  useEffect(() => {
    return () => {
      ctxRef.current?.close();
    };
  }, []);

  return { muted, setMuted, click, success, warp, error };
}