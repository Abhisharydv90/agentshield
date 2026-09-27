"use client";

import { createContext, useContext, useState, type ReactNode } from "react";

export type Phase = "idle" | "warp" | "arrived";

type Ctx = {
  phase: Phase;
  triggerWarp: () => void;
  reset: () => void;
};

const AuthTransitionContext = createContext<Ctx | null>(null);

export function AuthTransitionProvider({ children }: { children: ReactNode }) {
  const [phase, setPhase] = useState<Phase>("idle");
  return (
    <AuthTransitionContext.Provider
      value={{
        phase,
        triggerWarp: () => setPhase("warp"),
        reset: () => setPhase("idle"),
      }}
    >
      {children}
    </AuthTransitionContext.Provider>
  );
}

export function useAuthTransition() {
  const ctx = useContext(AuthTransitionContext);
  if (!ctx) throw new Error("useAuthTransition must be inside AuthTransitionProvider");
  return ctx;
}