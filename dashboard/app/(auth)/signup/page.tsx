"use client";

import { useState, useEffect, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  UserPlus,
  AlertCircle,
  Loader2,
  ArrowRight,
  ArrowLeft,
  Mail,
  Building2,
  Lock,
  User,
  Sparkles,
} from "lucide-react";
import { auth, ApiError } from "@/lib/auth-client";
import { TerminalBoot, buildSignupBootLines } from "@/components/auth/TerminalBoot";
import { ApiKeyReveal } from "@/components/auth/ApiKeyReveal";
import { useAuthTransition } from "@/components/auth3d/context";
import { useSynthAudio } from "@/components/auth3d/useSynthAudio";

type Step = "identity" | "workspace" | "provisioning" | "reveal";

export default function SignupPage() {
  const router = useRouter();
  const { triggerWarp } = useAuthTransition();
  const { click, success, error: errorSfx } = useSynthAudio();

  const [step, setStep] = useState<Step>("identity");
  const [stepKey, setStepKey] = useState(0); // forces card flip on step change

  // Form data
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [tenantName, setTenantName] = useState("");
  const [password, setPassword] = useState("");

  const [error, setError] = useState<string | null>(null);
  const [apiKey, setApiKey] = useState<string | null>(null);
  const [focusedField, setFocusedField] = useState<string | null>(null);

  // Bump stepKey whenever the step changes to retrigger the CSS animation
  useEffect(() => {
    setStepKey((k) => k + 1);
  }, [step]);

  function goToStep(next: Step) {
    click();
    setStep(next);
  }

  function nextFromIdentity(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (!name.trim() || !email.trim()) {
      errorSfx();
      setError("Name and email are required.");
      return;
    }
    goToStep("workspace");
  }

  async function nextFromWorkspace(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (!tenantName.trim() || !password) {
      errorSfx();
      setError("Workspace name and password are required.");
      return;
    }
    goToStep("provisioning");

    try {
      const res = await auth.signup({
        email,
        password,
        name,
        tenant_name: tenantName,
      });
      success();
      // Keep the API key but wait for terminal animation to finish
      setApiKey(res.api_key);
    } catch (err) {
      errorSfx();
      let msg = "Signup failed.";
      if (err instanceof ApiError) {
        if (Array.isArray(err.detail)) {
          msg = err.detail.map((d: any) => d.msg).join(" · ");
        } else if (typeof err.detail === "string") {
          msg = err.detail;
        }
      }
      setError(msg);
      setStep("workspace");
    }
  }

  // Shared wrapper that applies the card-flip animation on every step change
  const cardProps = {
    className:
      "relative bg-black/80 backdrop-blur-2xl border border-emerald-500/20 p-7",
    style: {
      transformStyle: "preserve-3d" as const,
      animation: "cardFlip 0.55s cubic-bezier(0.34,1.56,0.64,1)",
    },
  };

  /* ==================================================
     STEP 1 — Identity
     ================================================== */
  if (step === "identity") {
    return (
      <div key={stepKey} {...cardProps}>
        <CornerBrackets />
        <StepIndicator
          current={1}
          total={3}
          labels={["Identity", "Workspace", "Provision"]}
        />

        <div className="flex items-center gap-2 mb-1">
          <UserPlus className="w-4 h-4 text-emerald-400" />
          <h1 className="text-sm font-mono tracking-[0.28em] uppercase text-slate-300">
            Create Workspace
          </h1>
        </div>
        <p className="text-[10px] font-mono text-slate-600 mb-6 leading-relaxed">
          Step 1 of 3 · Identify yourself to begin provisioning
        </p>

        <form onSubmit={nextFromIdentity} className="space-y-4">
          <Field
            label="Your Name"
            icon={<User className="w-3 h-3" />}
            value={name}
            onChange={setName}
            placeholder="Jane Founder"
            autoComplete="name"
            autoFocus
            focused={focusedField === "name"}
            onFocus={() => setFocusedField("name")}
            onBlur={() => setFocusedField(null)}
          />
          <Field
            label="Email"
            icon={<Mail className="w-3 h-3" />}
            type="email"
            value={email}
            onChange={setEmail}
            placeholder="you@company.com"
            autoComplete="email"
            focused={focusedField === "email"}
            onFocus={() => setFocusedField("email")}
            onBlur={() => setFocusedField(null)}
          />

          {error && <ErrorBox message={error} />}

          <button
            type="submit"
            className="w-full bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/50 text-emerald-300 py-2.5 text-[11px] font-mono tracking-[0.25em] uppercase transition-all flex items-center justify-center gap-2 hover:scale-[1.01] active:scale-[0.99]"
          >
            Continue
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </form>

        <SignupFooter />
      </div>
    );
  }

  /* ==================================================
     STEP 2 — Workspace
     ================================================== */
  if (step === "workspace") {
    return (
      <div key={stepKey} {...cardProps}>
        <CornerBrackets />
        <StepIndicator
          current={2}
          total={3}
          labels={["Identity", "Workspace", "Provision"]}
        />

        <div className="flex items-center gap-2 mb-1">
          <Building2 className="w-4 h-4 text-emerald-400" />
          <h1 className="text-sm font-mono tracking-[0.28em] uppercase text-slate-300">
            Name your workspace
          </h1>
        </div>
        <p className="text-[10px] font-mono text-slate-600 mb-6 leading-relaxed">
          Step 2 of 3 · This becomes your isolated tenant slug
        </p>

        <form onSubmit={nextFromWorkspace} className="space-y-4">
          <Field
            label="Workspace Name"
            icon={<Building2 className="w-3 h-3" />}
            value={tenantName}
            onChange={setTenantName}
            placeholder="Acme Corp"
            autoFocus
            focused={focusedField === "tenant"}
            onFocus={() => setFocusedField("tenant")}
            onBlur={() => setFocusedField(null)}
          />
          <Field
            label="Password"
            icon={<Lock className="w-3 h-3" />}
            type="password"
            value={password}
            onChange={setPassword}
            placeholder="Min 8 chars · letter + digit"
            autoComplete="new-password"
            hint="Argon2id-hashed. Never stored in plaintext."
            focused={focusedField === "password"}
            onFocus={() => setFocusedField("password")}
            onBlur={() => setFocusedField(null)}
          />

          {error && <ErrorBox message={error} />}

          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => goToStep("identity")}
              className="flex-1 bg-black/40 hover:bg-slate-800/40 border border-slate-700/50 text-slate-400 py-2.5 text-[11px] font-mono tracking-[0.25em] uppercase transition-all flex items-center justify-center gap-2 hover:scale-[1.01] active:scale-[0.99]"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              Back
            </button>
            <button
              type="submit"
              className="flex-[2] bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/50 text-emerald-300 py-2.5 text-[11px] font-mono tracking-[0.25em] uppercase transition-all flex items-center justify-center gap-2 hover:scale-[1.01] active:scale-[0.99]"
            >
              Provision
              <Sparkles className="w-3.5 h-3.5" />
            </button>
          </div>
        </form>
      </div>
    );
  }

  /* ==================================================
     STEP 3 — Provisioning (terminal boot)
     ================================================== */
  if (step === "provisioning") {
    const lines = buildSignupBootLines(tenantName || "workspace");

    return (
      <div key={stepKey} {...cardProps}>
        <CornerBrackets />
        <StepIndicator
          current={3}
          total={3}
          labels={["Identity", "Workspace", "Provision"]}
        />

        <div className="flex items-center gap-2 mb-1">
          <Loader2 className="w-4 h-4 text-emerald-400 animate-spin" />
          <h1 className="text-sm font-mono tracking-[0.28em] uppercase text-slate-300">
            Provisioning
          </h1>
        </div>
        <p className="text-[10px] font-mono text-slate-600 mb-5 leading-relaxed">
          Step 3 of 3 · Setting up your isolated workspace
        </p>

        <TerminalBoot
          lines={lines}
          done={!!apiKey}
          onDone={() => {
            setTimeout(() => {
              success();
              setStep("reveal");
            }, 800);
          }}
        />
      </div>
    );
  }

  /* ==================================================
     STEP 4 — Reveal (API key + live tester)
     ================================================== */
  return (
    <div key={stepKey} {...cardProps}>
      <CornerBrackets />
      <ApiKeyReveal
        apiKey={apiKey!}
        onContinue={() => {
          success();
          // Fire the 3D Earth warp — pushes to "/" when the animation ends.
          triggerWarp();
        }}
      />
    </div>
  );
}

/* ============================================================
   Shared pieces
   ============================================================ */

function CornerBrackets() {
  return (
    <>
      <span className="absolute top-0 left-0 w-2.5 h-2.5 border-l border-t border-emerald-500/40" />
      <span className="absolute top-0 right-0 w-2.5 h-2.5 border-r border-t border-emerald-500/40" />
      <span className="absolute bottom-0 left-0 w-2.5 h-2.5 border-l border-b border-emerald-500/40" />
      <span className="absolute bottom-0 right-0 w-2.5 h-2.5 border-r border-b border-emerald-500/40" />
    </>
  );
}

function StepIndicator({
  current,
  total,
  labels,
}: {
  current: number;
  total: number;
  labels: string[];
}) {
  return (
    <div className="flex items-center gap-1 mb-5">
      {Array.from({ length: total }).map((_, i) => {
        const n = i + 1;
        const isActive = n === current;
        const isDone = n < current;
        return (
          <div key={i} className="flex-1 flex items-center gap-1">
            <div className="flex-1 flex flex-col gap-1">
              <div
                className={`h-0.5 transition-all duration-500 ${
                  isDone || isActive ? "bg-emerald-400" : "bg-slate-800"
                }`}
                style={{
                  boxShadow: isActive
                    ? "0 0 8px rgba(52,211,153,0.6)"
                    : "none",
                }}
              />
              <span
                className={`text-[8px] font-mono tracking-widest uppercase transition-colors ${
                  isActive
                    ? "text-emerald-400"
                    : isDone
                    ? "text-emerald-500/60"
                    : "text-slate-700"
                }`}
              >
                {labels[i]}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function ErrorBox({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-2 bg-rose-500/10 border border-rose-500/30 px-3 py-2 text-[11px] font-mono text-rose-300 animate-[cardFlip_0.3s_ease-out]">
      <AlertCircle className="w-3.5 h-3.5 shrink-0 mt-px" />
      <span>{message}</span>
    </div>
  );
}

function SignupFooter() {
  return (
    <div className="mt-6 pt-5 border-t border-emerald-500/10 text-center text-[10px] font-mono tracking-wider text-slate-500">
      Already have an account?{" "}
      <Link
        href="/login"
        className="text-emerald-400 hover:text-emerald-300 transition-colors"
      >
        Sign in →
      </Link>
    </div>
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
  hint,
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
  hint?: string;
  focused: boolean;
  onFocus: () => void;
  onBlur: () => void;
}) {
  return (
    <div
      className="transition-all duration-300"
      style={{
        transform: focused
          ? "translateZ(20px) translateY(-2px)"
          : "translateZ(0)",
      }}
    >
      <label className="flex items-center gap-1.5 text-[9px] font-mono tracking-[0.28em] text-slate-500 uppercase mb-1.5">
        <span className="text-emerald-500/60">{icon}</span>
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
            ? "border-emerald-500/60 shadow-[0_0_0_4px_rgba(16,185,129,0.1),0_8px_24px_-8px_rgba(16,185,129,0.4)]"
            : "border-emerald-500/20"
        }`}
      />
      {hint && (
        <div className="text-[9px] font-mono text-slate-700 mt-1.5">{hint}</div>
      )}
    </div>
  );
}