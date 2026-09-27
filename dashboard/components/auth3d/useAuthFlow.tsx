"use client";

import { createContext, useContext, useState, type ReactNode } from "react";

export type FlowStage =
  | "idle"
  | "typing"
  | "hashing"
  | "verifying"
  | "granted"
  | "denied";

type Ctx = {
  stage: FlowStage;
  setStage: (s: FlowStage) => void;
  // log lines pushed by the auth flow
  lines: string[];
  pushLine: (line: string) => void;
  clearLines: () => void;
  // packet flight trigger
  flightToken: string | null;
  triggerFlight: (token: string) => void;
  clearFlight: () => void;
};

const FlowContext = createContext<Ctx | null>(null);

export function useAuthFlow() {
  const ctx = useContext(FlowContext);
  if (!ctx) throw new Error("useAuthFlow must be inside AuthFlowProvider");
  return ctx;
}

export function AuthFlowProvider({ children }: { children: ReactNode }) {
  const [stage, setStage] = useState<FlowStage>("idle");
  const [lines, setLines] = useState<string[]>([]);
  const [flightToken, setFlightToken] = useState<string | null>(null);

  return (
    <FlowContext.Provider
      value={{
        stage,
        setStage,
        lines,
        pushLine: (line) => setLines((prev) => [...prev, line]),
        clearLines: () => setLines([]),
        flightToken,
        triggerFlight: (t) => {
          setFlightToken(t);
          setTimeout(() => setFlightToken(null), 1200);
        },
        clearFlight: () => setFlightToken(null),
      }}
    >
      {children}
    </FlowContext.Provider>
  );
}