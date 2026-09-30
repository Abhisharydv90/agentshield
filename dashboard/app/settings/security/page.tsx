"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldCheck,
  Loader2,
  AlertCircle,
  CheckCircle2,
  Copy,
  ArrowLeft,
  KeyRound,
} from "lucide-react";
import { apiFetch } from "@/lib/csrf";

export default function SecuritySettingsPage() {
  const [status, setStatus] = useState<{ enabled: boolean } | null>(null);
  const [setup, setSetup] = useState<{
    secret: string;
    qr_data_url: string;
  } | null>(null);
  const [code, setCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    apiFetch("/api/auth/2fa/status")
      .then((r) => r.json())
      .then(setStatus)
      .catch(() => setError("Failed to load status"));
  }, []);

  async function beginSetup() {
    setError(null);
    setLoading(true);
    try {
      const r = await apiFetch("/api/auth/2fa/setup", { method: "POST" });
      if (!r.ok) {
        const data = await r.json().catch(() => ({}));
        throw new Error(data?.error || `HTTP ${r.status}`);
      }
      setSetup(await r.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  async function confirmSetup() {
    if (!setup || code.length !== 6) return;
    setError(null);
    setLoading(true);
    try {
      const r = await apiFetch("/api/auth/2fa/verify-setup", {
        method: "POST",
        body: JSON.stringify({ code }),
      });
      if (!r.ok) {
        const data = await r.json().catch(() => ({}));
        throw new Error(data?.error || "Invalid code");
      }
      const data = await r.json();
      setRecoveryCodes(data.recovery_codes);
      setStatus({ enabled: true });
      setSetup(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  function copyRecovery() {
    if (!recoveryCodes) return;
    navigator.clipboard.writeText(recoveryCodes.join("\n"));
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }

  return (
    <main className="min-h-screen bg-black text-slate-200 px-8 py-16">
      <div className="max-w-[640px] mx-auto">
        <Link
          href="/dashboard"
          className="inline-flex items-center gap-2 text-[12px] font-mono tracking-widest uppercase text-slate-500 hover:text-[#7dd3fc] transition-colors mb-10"
        >
          <ArrowLeft className="w-3 h-3" />
          Back to dashboard
        </Link>

        <div className="text-[11px] font-mono tracking-[0.22em] uppercase text-[#7dd3fc] mb-4">
          Security
        </div>
        <h1
          className="text-[48px] leading-[1.05] tracking-[-0.03em] text-white mb-4"
          style={{ fontFamily: "Georgia, serif" }}
        >
          Two-factor
          <br />
          <em className="italic text-slate-500">authentication.</em>
        </h1>
        <p className="text-[15px] text-slate-400 mb-12 leading-relaxed">
          Add a second factor to your account. Compatible with Google
          Authenticator, 1Password, Authy, and any RFC 6238 client.
        </p>

        {recoveryCodes && (
          <div className="bg-white/[0.03] border border-[#7dd3fc]/30 rounded-xl p-6 mb-8">
            <div className="flex items-center gap-3 mb-4">
              <CheckCircle2 className="w-5 h-5 text-[#7dd3fc]" />
              <div className="text-[16px] text-white font-medium">
                Save your recovery codes
              </div>
            </div>
            <p className="text-[13px] text-slate-400 mb-4 leading-relaxed">
              These are the only way to sign in if you lose your device. Each
              can only be used once.
            </p>
            <div className="grid grid-cols-2 gap-2 font-mono text-[13px] text-slate-300 mb-4">
              {recoveryCodes.map((c) => (
                <div
                  key={c}
                  className="bg-black/40 border border-white/[0.06] px-3 py-2 rounded"
                >
                  {c}
                </div>
              ))}
            </div>
            <button
              onClick={copyRecovery}
              className="text-[12px] font-mono tracking-wider uppercase text-[#7dd3fc] hover:text-white transition-colors flex items-center gap-2"
            >
              {copied ? <CheckCircle2 className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
              {copied ? "Copied" : "Copy all"}
            </button>
          </div>
        )}

        {status && !status.enabled && !setup && (
          <button
            onClick={beginSetup}
            disabled={loading}
            className="inline-flex items-center gap-2 bg-white text-black px-6 py-3 text-[14px] font-medium rounded-lg hover:bg-slate-200 transition-colors disabled:opacity-50"
          >
            {loading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <ShieldCheck className="w-4 h-4" />
            )}
            Enable 2FA
          </button>
        )}

        {setup && (
          <div className="bg-white/[0.03] border border-white/[0.08] rounded-xl p-6">
            <div className="flex items-center gap-3 mb-5">
              <KeyRound className="w-5 h-5 text-[#7dd3fc]" />
              <div className="text-[16px] text-white font-medium">
                Scan this QR code
              </div>
            </div>

            <div className="bg-white p-4 rounded-lg inline-block mb-5">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={setup.qr_data_url}
                alt="TOTP QR code"
                className="w-[200px] h-[200px]"
              />
            </div>

            <div className="mb-5">
              <div className="text-[11px] font-mono tracking-wider uppercase text-slate-500 mb-2">
                Or enter this secret manually
              </div>
              <div className="font-mono text-[13px] text-slate-300 bg-black/40 border border-white/[0.06] px-3 py-2 rounded break-all">
                {setup.secret}
              </div>
            </div>

            <div className="mb-5">
              <label className="block text-[11px] font-mono tracking-wider uppercase text-slate-500 mb-2">
                Enter the 6-digit code from your app
              </label>
              <input
                value={code}
                onChange={(e) =>
                  setCode(e.target.value.replace(/\D/g, "").slice(0, 6))
                }
                inputMode="numeric"
                placeholder="000000"
                className="w-full bg-black/60 border border-white/[0.1] px-4 py-3 text-[16px] font-mono text-white text-center tracking-[0.4em] rounded-lg focus:outline-none focus:border-[#7dd3fc]/60"
              />
            </div>

            <button
              onClick={confirmSetup}
              disabled={code.length !== 6 || loading}
              className="w-full bg-white text-black py-3 text-[13px] font-medium rounded-lg hover:bg-slate-200 transition-colors disabled:opacity-40"
            >
              {loading ? "Verifying…" : "Confirm and enable"}
            </button>
          </div>
        )}

        {status?.enabled && !recoveryCodes && (
          <div className="bg-[#7dd3fc]/5 border border-[#7dd3fc]/30 rounded-xl p-5 flex items-center gap-3">
            <CheckCircle2 className="w-5 h-5 text-[#7dd3fc]" />
            <div>
              <div className="text-[14px] text-white">2FA is enabled</div>
              <div className="text-[12px] text-slate-400">
                Your account is protected.
              </div>
            </div>
          </div>
        )}

        {error && (
          <div className="mt-6 flex items-start gap-2 bg-rose-500/10 border border-rose-500/30 px-4 py-3 text-[13px] text-rose-300 rounded-lg">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}
      </div>
    </main>
  );
}