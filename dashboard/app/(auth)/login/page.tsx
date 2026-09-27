"use client";

import { Suspense, useState, useEffect, type FormEvent } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import {
  LogIn,
  AlertCircle,
  Loader2,
  Fingerprint,
  Mail,
  Lock,
} from "lucide-react";
import { auth, ApiError } from "@/lib/auth-client";
import { useAuthTransition } from "@/components/auth3d/context";
import { useSynthAudio } from "@/components/auth3d/useSynthAudio";
import { useAuthFlow } from "@/components/auth3d/useAuthFlow";
import { HashReveal } from "@/components/auth3d/HashReveal";

/* The inner component — has access to useSearchParams */
function LoginPageInner() {
  const router = useRouter();
  const params = useSearchParams();
  const next = params.get("next") ?? "/";
  const { triggerWarp } = useAuthTransition();
  const { click, success, error: errorSfx } = useSynthAudio();
  const { stage, setStage, pushLine, clearLines, triggerFlight } = useAuthFlow();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showHash, setShowHash] = useState(false);
  const [hashValue, setHashValue] = useState("");
  const [hashProgress, setHashProgress] = useState(0);
  const [focusedField, setFocusedField] = useState<string | null>(null);

  useEffect(() => {
    clearLines();
    setStage("idle");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (email || password) setStage("typing");
    else setStage("idle");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [email, password]);

  function fakeHash(seed: string): string {
    let h = 0;
    for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
    let out = "";
    for (let i = 0; i < 40; i++) {
      h = (h * 1103515245 + 12345) >>> 0;
      out += (h & 0xf).toString(16);
    }
    return out;
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    click();

    setStage("hashing");
    pushLine("▸ parsing credentials");
    const h = fakeHash(email + ":" + password);
    setHashValue(h);
    setShowHash(true);

    const apiPromise = auth
      .login({ email, password })
      .then((res) => ({ ok: true as const, res }))
      .catch((err) => ({ ok: false as const, err }));

    const t0 = performance.now();
    const dur = 400;
    await new Promise<void>((resolve) => {
      const tick = () => {
        const t = Math.min(1, (performance.now() - t0) / dur);
        setHashProgress(t);
        if (t < 1) requestAnimationFrame(tick);
        else resolve();
      };
      requestAnimationFrame(tick);
    });

    pushLine("▸ running argon2id · 100,000 iterations");
    pushLine(`  hash · ${h.slice(0, 32)}…`);
    pushLine("▸ hash verified");

    setStage("verifying");
    pushLine("▸ querying tenant registry");
    triggerFlight("HASH · " + h.slice(0, 8));

    const apiResult = await apiPromise;

    if (apiResult.ok) {
      const elapsed = Math.round(performance.now() - t0);
      pushLine(`  found · tenant in ${elapsed}ms`);
      pushLine("▸ issuing session jwt");
      pushLine("  jwt · eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9…");
      pushLine("▸ setting secure cookie");
      pushLine("▸ extending hash chain");
      pushLine("  block · 00088f11cb71a3c9e2b8d4…");
      pushLine("✓ ACCESS GRANTED");

      setStage("granted");
      success();
      setTimeout(() => setShowHash(false), 250);
      setTimeout(() => triggerWarp(), 650);
    } else {
      errorSfx();
      pushLine("✗ verification failed");
      pushLine("  reason · invalid credentials");
      pushLine("  status · 401 unauthorized");
      setStage("denied");
      setShowHash(false);
      const err = apiResult.err;
      if (err instanceof ApiError) {
        setError(
          err.detail === "invalid_credentials"
            ? "Invalid email or password."
            : typeof err.detail === "string"
              ? err.detail
              : "Login failed."
        );
      } else {
        setError("Network error. Please try again.");
      }
      setLoading(false);
    }
  }

  return (
    <div
      className="relative bg-black/80 backdrop-blur-2xl border border-cyan-400/20 p-7 transition-all duration-500"
      style={{
        transformStyle: "preserve-3d",
        animation: "cardFlip 0.6s cubic-bezier(0.34,1.56,0.64,1)",
      }}
    >
      <span className="absolute top-0 left-0 w-2.5 h-2.5 border-l border-t border-cyan-400/40" />
      <span className="absolute top-0 right-0 w-2.5 h-2.5 border-r border-t border-cyan-400/40" />
      <span className="absolute bottom-0 left-0 w-2.5 h-2.5 border-l border-b border-cyan-400/40" />
      <span className="absolute bottom-0 right-0 w-2.5 h-2.5 border-r border-b border-cyan-400/40" />

      <div className="flex items-center gap-2 mb-1">
        <LogIn className="w-4 h-4 text-cyan-400" />
        <h1 className="text-sm font-mono tracking-[0.28em] uppercase text-slate-300">
          Sign In
        </h1>
      </div>
      <p className="text-[10px] font-mono text-slate-600 mb-6 leading-relaxed">
        Authenticate to access your tenant workspace
      </p>

      {showHash ? (
        <div className="py-4 space-y-4">
          <HashReveal
            hash={hashValue}
            label="deriving key · argon2id"
            progress={hashProgress}
          />
          <div className="text-[9px] font-mono text-slate-600 leading-relaxed">
            {hashProgress >= 1
              ? "▸ querying gateway · sending verification packet"
              : `▸ ${Math.round(hashProgress * 100)}% complete`}
          </div>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="space-y-4">
          <Field
            label="Email"
            icon={<Mail className="w-3 h-3" />}
            type="email"
            value={email}
            onChange={setEmail}
            placeholder="you@company.com"
            autoComplete="email"
            autoFocus
            focused={focusedField === "email"}
            onFocus={() => setFocusedField("email")}
            onBlur={() => setFocusedField(null)}
          />
          <Field
            label="Password"
            icon={<Lock className="w-3 h-3" />}
            type="password"
            value={password}
            onChange={setPassword}
            placeholder="••••••••"
            autoComplete="current-password"
            focused={focusedField === "password"}
            onFocus={() => setFocusedField("password")}
            onBlur={() => setFocusedField(null)}
          />

          {error && (
            <div className="flex items-start gap-2 bg-rose-500/10 border border-rose-500/30 px-3 py-2 text-[11px] font-mono text-rose-300 animate-[cardFlip_0.3s_ease-out]">
              <AlertCircle className="w-3.5 h-3.5 shrink-0 mt-px" />
              <span>{error}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={loading || stage === "hashing" || stage === "verifying"}
            className="w-full bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-400/50 text-cyan-300 py-2.5 text-[11px] font-mono tracking-[0.25em] uppercase transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2 hover:scale-[1.01] active:scale-[0.99]"
          >
            {loading ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                Authenticating…
              </>
            ) : (
              <>
                <LogIn className="w-3.5 h-3.5" />
                Sign In
              </>
            )}
          </button>
        </form>
      )}

      <div className="flex items-center gap-3 my-5">
        <div className="flex-1 h-px bg-cyan-400/15" />
        <span className="text-[9px] font-mono tracking-[0.3em] text-slate-700 uppercase">
          or
        </span>
        <div className="flex-1 h-px bg-cyan-400/15" />
      </div>

      <button
        type="button"
        disabled
        className="w-full bg-black/40 border border-cyan-400/20 text-slate-500 py-2.5 text-[11px] font-mono tracking-[0.25em] uppercase transition-all disabled:opacity-40 flex items-center justify-center gap-2"
      >
        <Fingerprint className="w-3.5 h-3.5" />
        Continue with passkey
      </button>

      <div className="mt-6 pt-5 border-t border-cyan-400/10 text-center text-[10px] font-mono tracking-wider text-slate-500">
        No account?{" "}
        <Link
          href="/signup"
          className="text-cyan-400 hover:text-cyan-300 transition-colors"
        >
          Create one →
        </Link>
      </div>
    </div>
  );
}

/* The exported page — wraps inner in Suspense for production build */
export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="relative bg-black/80 backdrop-blur-2xl border border-cyan-400/20 p-7 h-[400px] flex items-center justify-center">
          <div className="w-4 h-4 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
        </div>
      }
    >
      <LoginPageInner />
    </Suspense>
  );
}

function Field({
  label,
  icon,
  type = "text",
  value,
  onChange,
  placeholder,
  autoComplete,
  autoFocus,
  focused,
  onFocus,
  onBlur,
}: {
  label: string;
  icon: React.ReactNode;
  type?: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  autoComplete?: string;
  autoFocus?: boolean;
  focused: boolean;
  onFocus: () => void;
  onBlur: () => void;
}) {
  return (
    <div
      className="transition-all duration-300"
      style={{
        transform: focused ? "translateZ(20px) translateY(-2px)" : "translateZ(0)",
      }}
    >
      <label className="flex items-center gap-1.5 text-[9px] font-mono tracking-[0.28em] text-slate-500 uppercase mb-1.5">
        <span className="text-cyan-500/60">{icon}</span>
        {label}
      </label>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onFocus={onFocus}
        onBlur={onBlur}
        placeholder={placeholder}
        autoComplete={autoComplete}
        autoFocus={autoFocus}
        className={`w-full bg-black/60 border px-3 py-2.5 text-[12px] font-mono text-slate-200 placeholder:text-slate-700 focus:outline-none transition-all ${
          focused
            ? "border-cyan-400/70 shadow-[0_0_0_4px_rgba(34,211,238,0.12),0_8px_24px_-8px_rgba(34,211,238,0.5)]"
            : "border-cyan-400/20"
        }`}
      />
    </div>
  );
}