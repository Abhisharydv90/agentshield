"use client";

import { useEffect, useRef, useState } from "react";
import { Activity, Database, Server, Terminal, Shield, Wifi } from "lucide-react";
import { useAuthFlow } from "./useAuthFlow";
import { TypewriterLog } from "./TypewriterLog";

function NodeIndicator({
  name,
  icon,
  latency,
  color,
  active,
}: {
  name: string;
  icon: React.ReactNode;
  latency: string;
  color: string;
  active: boolean;
}) {
  return (
    <div
      className={`flex items-center gap-2 px-2.5 py-1.5 border transition-all ${
        active
          ? "border-cyan-400/50 bg-cyan-500/[0.08]"
          : "border-cyan-400/15 bg-black/40"
      }`}
      data-node={name}
    >
      <span
        className="w-1.5 h-1.5 rounded-full block animate-pulse"
        style={{ background: color, boxShadow: `0 0 8px ${color}` }}
      />
      <span className="text-cyan-400/70">{icon}</span>
      <div className="flex-1">
        <div className="text-[9px] font-mono tracking-widest text-slate-400 uppercase">
          {name}
        </div>
      </div>
      <div className="text-[9px] font-mono tabular-nums" style={{ color }}>
        {latency}
      </div>
    </div>
  );
}

function FlyingPacket() {
  const { flightToken } = useAuthFlow();
  if (!flightToken) return null;
  return (
    <div
      className="pointer-events-none fixed z-[80]"
      style={{
        left: "50%",
        top: "60%",
        animation: "packetFly 1.1s cubic-bezier(0.16, 1, 0.3, 1) forwards",
      }}
    >
      <div className="relative -translate-x-1/2">
        <div className="w-3 h-3 rounded-full bg-cyan-400 shadow-[0_0_24px_8px_rgba(34,211,238,0.6)]" />
        <div className="absolute inset-0 rounded-full bg-cyan-400/40 animate-ping" />
        <div className="absolute left-5 top-1/2 -translate-y-1/2 whitespace-nowrap text-[9px] font-mono tracking-widest text-cyan-300 bg-black/80 border border-cyan-400/50 px-2 py-0.5">
          {flightToken}
        </div>
      </div>
    </div>
  );
}

function useLiveStats() {
  const [stats, setStats] = useState({ latency: "0.6", throughput: "148", sessions: "1" });
  useEffect(() => {
    const t = setInterval(() => {
      setStats({
        latency: (0.3 + Math.random() * 0.7).toFixed(2),
        throughput: String(120 + Math.floor(Math.random() * 60)),
        sessions: String(1 + Math.floor(Math.random() * 4)),
      });
    }, 2000);
    return () => clearInterval(t);
  }, []);
  return stats;
}

export function ProtocolTerminal() {
  const { stage, lines } = useAuthFlow();
  const stats = useLiveStats();

  const stageLabel: Record<typeof stage, string> = {
    idle: "STANDBY",
    typing: "INBOUND",
    hashing: "DERIVING KEY",
    verifying: "VERIFYING",
    granted: "GRANTED",
    denied: "DENIED",
  };
  const stageColor: Record<typeof stage, string> = {
    idle: "#22d3ee",
    typing: "#67e8f9",
    hashing: "#f59e0b",
    verifying: "#a5f3fc",
    granted: "#22d3ee",
    denied: "#f43f5e",
  };
  const accent = stageColor[stage];
  const isActive = stage !== "idle";

  return (
    <>
      {/* Left rail */}
      <aside className="hidden lg:flex fixed left-6 top-1/2 -translate-y-1/2 z-30 w-[200px] flex-col gap-1.5 pointer-events-none">
        <div className="flex items-center gap-2 mb-1">
          <Activity className="w-3 h-3" style={{ color: accent }} />
          <span className="text-[9px] font-mono tracking-[0.3em] uppercase" style={{ color: accent }}>
            Gateway Nodes
          </span>
        </div>
        <NodeIndicator name="CLIENT" icon={<Wifi className="w-3 h-3" />} latency={`${stats.latency}ms`} color="#22d3ee" active={stage !== "idle"} />
        <NodeIndicator name="GATEWAY" icon={<Shield className="w-3 h-3" />} latency={`${stats.latency}ms`} color="#67e8f9" active={stage === "verifying" || stage === "granted"} />
        <NodeIndicator name="POSTGRES" icon={<Database className="w-3 h-3" />} latency="47ms" color="#f59e0b" active={stage === "hashing" || stage === "verifying"} />
        <NodeIndicator name="VAULT" icon={<Server className="w-3 h-3" />} latency="2ms" color="#a5f3fc" active={stage === "granted"} />
      </aside>

      {/* Right rail */}
      <aside className="hidden lg:flex fixed right-6 top-1/2 -translate-y-1/2 z-30 w-[310px] h-[460px] flex-col pointer-events-none">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <Terminal className="w-3 h-3" style={{ color: accent }} />
            <span className="text-[9px] font-mono tracking-[0.3em] uppercase" style={{ color: accent }}>
              Auth Flow · Live
            </span>
          </div>
          <span
            className="text-[9px] font-mono tracking-widest px-1.5 py-0.5 border"
            style={{ color: accent, borderColor: `${accent}66`, background: `${accent}12` }}
          >
            {stageLabel[stage]}
          </span>
        </div>
        <div className="relative flex-1 bg-black/75 backdrop-blur-2xl border border-cyan-400/15 p-3 overflow-hidden">
          <span className="absolute top-0 left-0 w-2 h-2 border-l border-t border-cyan-400/50" />
          <span className="absolute top-0 right-0 w-2 h-2 border-r border-t border-cyan-400/50" />
          <span className="absolute bottom-0 left-0 w-2 h-2 border-l border-b border-cyan-400/50" />
          <span className="absolute bottom-0 right-0 w-2 h-2 border-r border-b border-cyan-400/50" />
          <TypewriterLog lines={lines} />
        </div>
      </aside>

      {/* Bottom bar */}
      <div className="fixed bottom-0 left-0 right-0 z-30 flex items-center justify-between px-6 py-1.5 border-t border-cyan-400/15 bg-gradient-to-t from-black/90 to-transparent pointer-events-none">
        <div className="flex items-center gap-5 text-[9px] font-mono tracking-[0.3em] text-slate-600 uppercase">
          <span>
            SESSION · <span className="text-cyan-300/80">8F2A-91C4</span>
          </span>
          <span className="hidden md:inline">
            THROUGHPUT · <span className="text-cyan-300/80">{stats.throughput}/s</span>
          </span>
          <span className="hidden md:inline">
            LATENCY · <span className="text-cyan-300/80">{stats.latency}ms</span>
          </span>
        </div>
        <div className="flex items-center gap-2 text-[9px] font-mono tracking-[0.3em]">
          <span className="w-1 h-1 rounded-full animate-pulse" style={{ background: accent, boxShadow: `0 0 8px ${accent}` }} />
          <span style={{ color: accent }}>{stageLabel[stage]}</span>
        </div>
      </div>

      <FlyingPacket />

      {isActive && (
        <div
          key={stage}
          className="fixed inset-x-0 z-20 pointer-events-none h-[1px] animate-[scanDown_1.4s_ease-out_forwards]"
          style={{
            background: `linear-gradient(90deg, transparent, ${accent}80, transparent)`,
            boxShadow: `0 0 24px ${accent}66`,
          }}
        />
      )}
    </>
  );
}