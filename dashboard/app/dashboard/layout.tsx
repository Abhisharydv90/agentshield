"use client";

import { useEffect, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { ShieldCheck } from "lucide-react";

export default function DashboardLayout({ children }: { children: ReactNode }) {
  const router = useRouter();
  const [checked, setChecked] = useState(false);
  const [authed, setAuthed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/auth/me", { credentials: "include" })
      .then((r) => {
        if (cancelled) return;
        if (r.ok) {
          setAuthed(true);
        } else {
          router.replace("/login?next=/dashboard");
        }
      })
      .catch(() => {
        if (!cancelled) router.replace("/login?next=/dashboard");
      })
      .finally(() => {
        if (!cancelled) setChecked(true);
      });
    return () => {
      cancelled = true;
    };
  }, [router]);

  if (!checked) return <LoadingScreen />;
  if (!authed) return null;
  return <>{children}</>;
}

function LoadingScreen() {
  return (
    <div className="fixed inset-0 bg-black flex items-center justify-center">
      <div className="flex flex-col items-center gap-5">
        <div className="relative w-16 h-16">
          <div className="absolute inset-0 rounded-full border-2 border-emerald-500/20" />
          <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-emerald-400 animate-spin" />
          <ShieldCheck className="absolute inset-0 m-auto w-6 h-6 text-emerald-400" />
        </div>
        <div className="text-[10px] font-mono tracking-[0.3em] uppercase text-emerald-400/60">
          Verifying session
        </div>
      </div>
    </div>
  );
}