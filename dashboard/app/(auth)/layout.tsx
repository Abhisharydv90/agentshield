"use client";

import type { ReactNode } from "react";
import Link from "next/link";
import { Volume2, VolumeX } from "lucide-react";
import { AuthCanvas } from "@/components/auth3d/AuthCanvas";
import { CursorParticles } from "@/components/auth3d/CursorParticles";
import { AccessGranted } from "@/components/auth3d/AccessGranted";
import { AuthTransitionProvider } from "@/components/auth3d/context";
import { AuthFlowProvider } from "@/components/auth3d/useAuthFlow";
import { ProtocolTerminal } from "@/components/auth3d/ProtocolTerminal";
import { useSynthAudio } from "@/components/auth3d/useSynthAudio";

function MuteToggle() {
  const { muted, setMuted } = useSynthAudio();
  return (
    <button
      onClick={() => setMuted(!muted)}
      className="fixed top-6 right-6 z-50 w-9 h-9 flex items-center justify-center border border-cyan-500/25 text-slate-500 hover:text-cyan-300 hover:border-cyan-400/70 transition-colors backdrop-blur-md bg-black/40"
      title={muted ? "Unmute" : "Mute"}
    >
      {muted ? <VolumeX className="w-4 h-4" /> : <Volume2 className="w-4 h-4" />}
    </button>
  );
}

function AuthShell({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen bg-[#020810] text-slate-200 flex items-center justify-center p-6 relative overflow-hidden">
      <AuthCanvas />
      <CursorParticles />
      <AccessGranted />
      <ProtocolTerminal />
      <MuteToggle />

      {/* Full-screen corner brackets — cyan */}
      <div className="absolute inset-4 pointer-events-none z-10">
        <span className="absolute top-0 left-0 w-8 h-8 border-l-2 border-t-2 border-cyan-400/30" />
        <span className="absolute top-0 right-0 w-8 h-8 border-r-2 border-t-2 border-cyan-400/30" />
        <span className="absolute bottom-0 left-0 w-8 h-8 border-l-2 border-b-2 border-cyan-400/30" />
        <span className="absolute bottom-0 right-0 w-8 h-8 border-r-2 border-b-2 border-cyan-400/30" />
      </div>

      <div className="relative z-20 w-full max-w-md">
        {/* Logo — was ShieldLogo 3D, now inline SVG for reliability */}
        <Link href="/" className="block text-center mb-6 group">
          <div className="relative inline-block">
            <svg
              width="52"
              height="52"
              viewBox="0 0 52 52"
              className="mx-auto mb-3"
              style={{ filter: "drop-shadow(0 0 12px rgba(34,211,238,0.5))" }}
            >
              <path
                d="M26 4 L44 12 L44 28 C44 38 36 45 26 48 C16 45 8 38 8 28 L8 12 Z"
                fill="none"
                stroke="#22d3ee"
                strokeWidth="1.5"
                strokeLinejoin="round"
              />
              <path
                d="M17 26 L24 33 L37 18"
                fill="none"
                stroke="#22d3ee"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </div>
          <div className="text-[15px] font-bold tracking-[0.35em] text-white">
            AGENT<span className="text-cyan-400">SHIELD</span>
          </div>
          <div className="text-[8px] font-mono tracking-[0.4em] text-slate-500 uppercase mt-1">
            Autonomous Agent Firewall
          </div>
        </Link>

        {children}

        <div className="mt-8 text-center text-[10px] font-mono tracking-widest text-slate-600 flex items-center justify-center gap-2 pb-6">
          <span className="w-1 h-1 rounded-full bg-cyan-400/70 animate-pulse" />
          <span>AES-256-GCM · ZERO-TRUST · HASH-CHAINED</span>
        </div>
      </div>
    </div>
  );
}

export default function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <AuthTransitionProvider>
      <AuthFlowProvider>
        <AuthShell>{children}</AuthShell>
      </AuthFlowProvider>
    </AuthTransitionProvider>
  );
}