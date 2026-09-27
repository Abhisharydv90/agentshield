import type { Metadata } from "next";
import Link from "next/link";
import {
  ShieldCheck, Lock, EyeOff, Gavel, Zap, Activity, Layers,
  ArrowRight, Check, Terminal, Globe, Server, Database,
  AlertTriangle, Key, Network, FileSearch, ScrollText, Cloud,
} from "lucide-react";
import { HeroScene } from "@/components/landing/HeroScene";
import { LandingBackground } from "@/components/landing/LandingBackground";
import { ScrollReveal } from "@/components/landing/ScrollReveal";

export const metadata: Metadata = {
  title: "AgentShield · The Zero-Trust Firewall for AI Agents",
  description:
    "Block prompt injections, redact PII, and enforce policy on every AI agent action. Enterprise-grade security in a single line of code.",
};

/* ============================================================
   Nav
   ============================================================ */
function Nav() {
  return (
    <nav className="fixed top-0 left-0 right-0 z-50 backdrop-blur-xl bg-black/60 border-b border-cyan-500/15">
      <div className="max-w-[1400px] mx-auto px-6 py-3 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2.5 group">
          <div className="relative w-8 h-8 rounded-sm bg-cyan-400 flex items-center justify-center shadow-[0_0_20px_rgba(0,229,255,0.5)]">
            <ShieldCheck className="w-4 h-4 text-black" strokeWidth={2.5} />
          </div>
          <div>
            <div className="text-sm font-bold tracking-[0.2em] text-white leading-none">
              AGENT<span className="text-cyan-400 neon-text">SHIELD</span>
            </div>
            <div className="text-[7px] font-mono tracking-[0.3em] text-cyan-500/60 uppercase mt-0.5">
              Autonomous Agent Firewall
            </div>
          </div>
        </Link>

        <div className="hidden md:flex items-center gap-8 text-[11px] font-mono tracking-widest uppercase">
          <a href="#features" className="text-slate-400 hover:text-cyan-400 transition-colors">Features</a>
          <a href="#how" className="text-slate-400 hover:text-cyan-400 transition-colors">How it works</a>
          <a href="#security" className="text-slate-400 hover:text-cyan-400 transition-colors">Security</a>
          <a href="#pricing" className="text-slate-400 hover:text-cyan-400 transition-colors">Pricing</a>
        </div>

        <div className="flex items-center gap-3">
          <Link href="/login" className="text-[11px] font-mono tracking-widest text-slate-400 hover:text-cyan-400 transition-colors uppercase">
            Sign in
          </Link>
          <Link
            href="/signup"
            className="bg-cyan-400 hover:bg-cyan-300 text-black px-4 py-2 text-[11px] font-mono tracking-widest font-bold uppercase transition-all flex items-center gap-1.5 shadow-[0_0_24px_rgba(0,229,255,0.4)] hover:shadow-[0_0_32px_rgba(0,229,255,0.7)]"
          >
            Start free
            <ArrowRight className="w-3 h-3" />
          </Link>
        </div>
      </div>
    </nav>
  );
}

/* ============================================================
   Hero
   ============================================================ */
function Hero() {
  return (
    <section className="relative pt-32 pb-24 px-6 overflow-hidden min-h-[90vh]">
      <div className="absolute inset-0 z-0">
        <HeroScene />
      </div>

      <div className="absolute inset-0 z-[1] bg-[radial-gradient(ellipse_at_center,transparent_20%,rgba(0,0,0,0.85)_75%)] pointer-events-none" />

      <div className="absolute inset-6 pointer-events-none z-[2]">
        <span className="absolute top-0 left-0 w-10 h-10 border-l border-t border-cyan-400/25" />
        <span className="absolute top-0 right-0 w-10 h-10 border-r border-t border-cyan-400/25" />
        <span className="absolute bottom-0 left-0 w-10 h-10 border-l border-b border-cyan-400/25" />
        <span className="absolute bottom-0 right-0 w-10 h-10 border-r border-b border-cyan-400/25" />
      </div>

      <div className="relative max-w-[1200px] mx-auto z-10">
        <div className="flex justify-center mb-6">
          <div className="inline-flex items-center gap-2 border border-cyan-400/40 bg-cyan-500/5 px-3 py-1.5 backdrop-blur-sm">
            <span className="w-1 h-1 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_8px_rgba(0,229,255,1)]" />
            <span className="text-[9px] font-mono tracking-[0.3em] text-cyan-300 uppercase">
              OWASP LLM Top 10 · Production Ready
            </span>
          </div>
        </div>

        <h1 className="text-center text-5xl md:text-7xl lg:text-8xl font-bold tracking-tight text-white leading-[1.02]">
          The firewall for
          <br />
          <span className="neon-text bg-gradient-to-r from-cyan-300 via-cyan-400 to-amber-300 bg-clip-text text-transparent">
            AI agents
          </span>
        </h1>

        <p className="text-center max-w-2xl mx-auto mt-8 text-base md:text-lg text-slate-300 leading-relaxed">
          Block prompt injections, redact PII, and enforce policy on every tool
          call. Zero-trust security for agentic systems —{" "}
          <span className="text-cyan-300 neon-text">in a single line of code.</span>
        </p>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 mt-10">
          <Link
            href="/signup"
            className="group bg-cyan-400 hover:bg-cyan-300 text-black px-7 py-3.5 text-[12px] font-mono tracking-[0.25em] font-bold uppercase transition-all flex items-center gap-2 hover:scale-[1.03] shadow-[0_0_40px_rgba(0,229,255,0.5)] hover:shadow-[0_0_60px_rgba(0,229,255,0.8)]"
          >
            Start free
            <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
          </Link>
          <a
            href="#how"
            className="border border-cyan-400/40 hover:border-cyan-400/80 text-slate-200 hover:text-cyan-200 px-7 py-3.5 text-[12px] font-mono tracking-[0.25em] uppercase transition-all flex items-center gap-2 backdrop-blur-sm bg-black/30"
          >
            <Terminal className="w-4 h-4" />
            See how it works
          </a>
        </div>

        <div className="mt-16 max-w-3xl mx-auto relative">
          <div
            className="relative bg-black/80 backdrop-blur-2xl border border-cyan-400/30 p-6 neon-border"
          >
            <span className="absolute top-0 left-0 w-3 h-3 border-l border-t border-cyan-400/80" />
            <span className="absolute top-0 right-0 w-3 h-3 border-r border-t border-cyan-400/80" />
            <span className="absolute bottom-0 left-0 w-3 h-3 border-l border-b border-cyan-400/80" />
            <span className="absolute bottom-0 right-0 w-3 h-3 border-r border-b border-cyan-400/80" />

            <div className="flex items-center justify-between mb-4 pb-3 border-b border-cyan-400/15">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500/70" />
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500/70" />
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-500/70" />
              </div>
              <span className="text-[9px] font-mono tracking-widest text-cyan-400/70 uppercase">
                integration.py
              </span>
            </div>

            <pre className="text-[12px] font-mono leading-relaxed overflow-x-auto">
              <code>
                <span className="text-slate-600"># Before: exposed to prompt injection</span>
                {"\n"}
                <span className="text-cyan-300">response</span>
                <span className="text-slate-500"> = </span>
                <span className="text-amber-300">openai</span>
                <span className="text-slate-400">.chat.completions.create(</span>
                {"\n"}
                <span className="text-slate-500">{"    "}model=</span>
                <span className="text-emerald-300">"gpt-4o"</span>
                <span className="text-slate-400">, messages=[...]</span>
                {"\n"}
                <span className="text-slate-400">)</span>
                {"\n\n"}
                <span className="text-slate-600"># After: AgentShield protects every request</span>
                {"\n"}
                <span className="text-cyan-300">response</span>
                <span className="text-slate-500"> = </span>
                <span className="text-amber-300">openai</span>
                <span className="text-slate-400">.chat.completions.create(</span>
                {"\n"}
                <span className="text-slate-500">{"    "}model=</span>
                <span className="text-emerald-300">"gpt-4o"</span>
                <span className="text-slate-400">,</span>
                {"\n"}
                <span className="text-slate-500">{"    "}messages=[...],</span>
                {"\n"}
                <span className="text-amber-300">{"    "}base_url</span>
                <span className="text-slate-500">=</span>
                <span className="text-emerald-300">"https://gateway.agentshield.app/v1"</span>
                {"\n"}
                <span className="text-slate-400">)</span>
              </code>
            </pre>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ============================================================
   Trust bar
   ============================================================ */
function TrustBar() {
  const stats = [
    { value: "847", label: "Injection patterns" },
    { value: "< 50ms", label: "Proxy overhead" },
    { value: "99.98%", label: "Uptime SLA" },
    { value: "SHA-256", label: "Audit chain" },
  ];
  return (
    <section className="relative border-y border-cyan-400/15 bg-black/60 backdrop-blur-sm">
      <div className="max-w-[1400px] mx-auto px-6 py-10 grid grid-cols-2 md:grid-cols-4 gap-6">
        {stats.map((s, i) => (
          <ScrollReveal key={s.label} delay={i * 80}>
            <div className="text-center">
              <div className="text-3xl md:text-4xl font-mono font-bold text-cyan-400 tabular-nums neon-text">
                {s.value}
              </div>
              <div className="text-[9px] font-mono tracking-[0.3em] text-slate-500 uppercase mt-2">
                {s.label}
              </div>
            </div>
          </ScrollReveal>
        ))}
      </div>
    </section>
  );
}

/* ============================================================
   Features
   ============================================================ */
function Features() {
  const features = [
    { icon: <Lock className="w-5 h-5" />, title: "Inbound Injection Scanner", desc: "Three-stage detection: signature matching against 847 known patterns, unicode smuggling detection, and semantic vector similarity.", color: "#00e5ff" },
    { icon: <EyeOff className="w-5 h-5" />, title: "Zero-Trust PII Vault", desc: "Detect and swap PII — emails, SSNs, cards, API keys — before they reach the LLM. Reversible with HMAC-derived placeholders.", color: "#00ffa3" },
    { icon: <Gavel className="w-5 h-5" />, title: "LLM-as-a-Judge Circuit Breaker", desc: "Every tool call evaluated by a secondary LLM judge against your policy. Fail-closed by default. Streaming tool-call reassembly included.", color: "#ffb800" },
    { icon: <Layers className="w-5 h-5" />, title: "Tamper-Evident Audit Log", desc: "Every security event written to a per-tenant SHA-256 hash chain. Cryptographically impossible to modify without breaking the chain.", color: "#00e5ff" },
    { icon: <Zap className="w-5 h-5" />, title: "OpenAI-Compatible Proxy", desc: "Change one line in your code. Works with LangChain, LlamaIndex, MCP, or any custom orchestrator. No SDK to learn.", color: "#00ffa3" },
    { icon: <Activity className="w-5 h-5" />, title: "Real-Time Telemetry", desc: "Live dashboard showing injection block rates, PII redaction counts, judge decisions, token consumption, and latency budgets.", color: "#ffb800" },
  ];

  return (
    <section id="features" className="relative py-28 px-6">
      <div className="max-w-[1400px] mx-auto">
        <ScrollReveal>
          <div className="text-center mb-16">
            <div className="inline-flex items-center gap-2 mb-4">
              <span className="w-1 h-1 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(0,229,255,1)]" />
              <span className="text-[10px] font-mono tracking-[0.4em] text-cyan-300 uppercase">The Stack</span>
            </div>
            <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold tracking-tight text-white">
              Four defense layers.
              <br />
              <span className="text-slate-500">Zero trust by default.</span>
            </h2>
          </div>
        </ScrollReveal>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {features.map((f, i) => (
            <ScrollReveal key={f.title} delay={i * 60}>
              <div className="feature-card relative bg-black/60 backdrop-blur-xl border border-cyan-400/15 p-6 h-full">
                <span className="absolute top-0 left-0 w-2 h-2 border-l border-t border-cyan-400/50" />
                <span className="absolute top-0 right-0 w-2 h-2 border-r border-t border-cyan-400/50" />
                <span className="absolute bottom-0 left-0 w-2 h-2 border-l border-b border-cyan-400/50" />
                <span className="absolute bottom-0 right-0 w-2 h-2 border-r border-b border-cyan-400/50" />
                <div
                  className="w-11 h-11 flex items-center justify-center mb-4 border"
                  style={{
                    color: f.color,
                    borderColor: `${f.color}50`,
                    background: `${f.color}0a`,
                    boxShadow: `0 0 20px ${f.color}30`,
                  }}
                >
                  {f.icon}
                </div>
                <h3 className="text-base font-semibold text-white mb-2 tracking-tight">{f.title}</h3>
                <p className="text-[13px] text-slate-400 leading-relaxed">{f.desc}</p>
              </div>
            </ScrollReveal>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ============================================================
   How it works
   ============================================================ */
function HowItWorks() {
  const steps = [
    { n: "01", title: "Point at the gateway", desc: "Change one URL in your agent code. Nothing else. Your agent now talks through AgentShield instead of directly to OpenAI.", icon: <Globe className="w-5 h-5" /> },
    { n: "02", title: "Every request scanned", desc: "Injection attempts are blocked with a 403. PII is redacted to reversible tokens. Attachments and tool calls are buffered and normalized.", icon: <ShieldCheck className="w-5 h-5" /> },
    { n: "03", title: "Every action judged", desc: "When the agent proposes a tool call — SQL, email, API — the circuit breaker evaluates it against policy. Malicious actions never execute.", icon: <Gavel className="w-5 h-5" /> },
    { n: "04", title: "Everything audited", desc: "A hash-chained log records every decision with its reasoning. Compliance teams get proof. Auditors get a cryptographic receipt.", icon: <Layers className="w-5 h-5" /> },
  ];
  return (
    <section id="how" className="relative py-28 px-6 border-t border-cyan-400/10">
      <div className="max-w-[1200px] mx-auto">
        <ScrollReveal>
          <div className="text-center mb-16">
            <div className="inline-flex items-center gap-2 mb-4">
              <span className="w-1 h-1 rounded-full bg-amber-400 shadow-[0_0_8px_rgba(255,184,0,1)]" />
              <span className="text-[10px] font-mono tracking-[0.4em] text-amber-300 uppercase">How it works</span>
            </div>
            <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold tracking-tight text-white">
              A firewall in front of every
              <br />
              <span className="text-cyan-400 neon-text">agent decision.</span>
            </h2>
          </div>
        </ScrollReveal>

        <div className="space-y-4">
          {steps.map((s, i) => (
            <ScrollReveal key={s.n} delay={i * 100}>
              <div className="relative grid grid-cols-1 md:grid-cols-[120px_1fr_2fr] gap-6 items-center bg-black/60 backdrop-blur-xl border border-cyan-400/15 p-6 hover:border-cyan-400/50 transition-all">
                <div className="text-6xl font-mono font-bold text-cyan-400/25 tabular-nums">{s.n}</div>
                <div className="flex items-center gap-3">
                  <div className="w-11 h-11 flex items-center justify-center border border-cyan-400/50 text-cyan-400 bg-cyan-500/5 shadow-[0_0_20px_rgba(0,229,255,0.2)]">
                    {s.icon}
                  </div>
                  <h3 className="text-lg font-semibold text-white">{s.title}</h3>
                </div>
                <p className="text-[13px] text-slate-400 leading-relaxed">{s.desc}</p>
              </div>
            </ScrollReveal>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ============================================================
   Security section
   ============================================================ */
function Security() {
  const items = [
    { icon: <AlertTriangle className="w-5 h-5" />, title: "LLM01 — Prompt Injection", desc: "Blocked at the gateway before reaching the model." },
    { icon: <EyeOff className="w-5 h-5" />, title: "LLM06 — Sensitive Info Disclosure", desc: "PII redaction with reversible vault and short TTL." },
    { icon: <Gavel className="w-5 h-5" />, title: "LLM07 — Insecure Plugin Design", desc: "Policy engine + tool allowlist enforced on every call." },
    { icon: <Key className="w-5 h-5" />, title: "LLM08 — Excessive Agency", desc: "Circuit breaker + human-in-the-loop approvals." },
    { icon: <FileSearch className="w-5 h-5" />, title: "LLM09 — Overreliance", desc: "Judge verdicts include confidence scores and reasoning." },
    { icon: <ScrollText className="w-5 h-5" />, title: "SOC 2 Evidence Export", desc: "Hash-chained audit trail for compliance teams." },
  ];
  return (
    <section id="security" className="relative py-28 px-6 border-t border-cyan-400/10 bg-gradient-to-b from-transparent via-cyan-950/5 to-transparent">
      <div className="max-w-[1200px] mx-auto">
        <ScrollReveal>
          <div className="text-center mb-16">
            <div className="inline-flex items-center gap-2 mb-4">
              <span className="w-1 h-1 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(0,229,255,1)]" />
              <span className="text-[10px] font-mono tracking-[0.4em] text-cyan-300 uppercase">OWASP Aligned</span>
            </div>
            <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold tracking-tight text-white">
              Built for the threats
              <br />
              <span className="text-slate-500">that matter in 2026.</span>
            </h2>
          </div>
        </ScrollReveal>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {items.map((item, i) => (
            <ScrollReveal key={item.title} delay={i * 60}>
              <div className="relative bg-black/60 backdrop-blur-xl border border-cyan-400/15 p-5 hover:border-amber-400/50 transition-all">
                <span className="absolute top-0 left-0 w-2 h-2 border-l border-t border-amber-400/60" />
                <span className="absolute bottom-0 right-0 w-2 h-2 border-r border-b border-amber-400/60" />
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-9 h-9 flex items-center justify-center border border-amber-400/40 text-amber-400 bg-amber-500/5">
                    {item.icon}
                  </div>
                  <h3 className="text-[13px] font-mono text-amber-300 tracking-wider">{item.title}</h3>
                </div>
                <p className="text-[12px] text-slate-400 leading-relaxed">{item.desc}</p>
              </div>
            </ScrollReveal>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ============================================================
   Pricing
   ============================================================ */
function Pricing() {
  const tiers = [
    { name: "Free", price: "$0", period: "forever", desc: "For developers exploring AgentShield.", features: ["10,000 requests / month", "Inbound injection scanning", "Basic PII redaction", "7-day audit log retention", "Community support"], cta: "Start free", highlight: false },
    { name: "Pro", price: "$99", period: "/ month", desc: "For teams shipping AI products to production.", features: ["500,000 requests / month", "All security features enabled", "LLM-as-a-Judge circuit breaker", "90-day audit log retention", "Slack + email alerts", "Email support, 24h response"], cta: "Start 14-day trial", highlight: true },
    { name: "Enterprise", price: "Custom", period: "", desc: "For teams with compliance and scale requirements.", features: ["Unlimited requests", "Self-hosted or private cloud", "SOC 2 evidence export", "SSO + audit API", "Dedicated solutions engineer", "99.99% uptime SLA"], cta: "Contact us", highlight: false },
  ];

  return (
    <section id="pricing" className="relative py-28 px-6 border-t border-cyan-400/10">
      <div className="max-w-[1300px] mx-auto">
        <ScrollReveal>
          <div className="text-center mb-16">
            <div className="inline-flex items-center gap-2 mb-4">
              <span className="w-1 h-1 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(0,229,255,1)]" />
              <span className="text-[10px] font-mono tracking-[0.4em] text-cyan-300 uppercase">Pricing</span>
            </div>
            <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold tracking-tight text-white">
              Simple pricing.
              <br />
              <span className="text-slate-500">No per-token surprises.</span>
            </h2>
          </div>
        </ScrollReveal>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {tiers.map((t, i) => (
            <ScrollReveal key={t.name} delay={i * 80}>
              <div
                className={`relative bg-black/70 backdrop-blur-2xl p-8 transition-all h-full ${
                  t.highlight
                    ? "border-2 border-cyan-400/70"
                    : "border border-cyan-400/15 hover:border-cyan-400/40"
                }`}
                style={t.highlight ? { boxShadow: "0 0 60px -15px rgba(0,229,255,0.6)" } : undefined}
              >
                {t.highlight && (
                  <>
                    <span className="absolute top-0 left-0 w-3 h-3 border-l-2 border-t-2 border-cyan-400" />
                    <span className="absolute top-0 right-0 w-3 h-3 border-r-2 border-t-2 border-cyan-400" />
                    <span className="absolute bottom-0 left-0 w-3 h-3 border-l-2 border-b-2 border-cyan-400" />
                    <span className="absolute bottom-0 right-0 w-3 h-3 border-r-2 border-b-2 border-cyan-400" />
                    <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-cyan-400 text-black px-3 py-1 text-[9px] font-mono tracking-[0.3em] font-bold uppercase shadow-[0_0_20px_rgba(0,229,255,0.7)]">
                      Most popular
                    </div>
                  </>
                )}
                <div className="text-[10px] font-mono tracking-[0.4em] text-cyan-300 uppercase mb-2">{t.name}</div>
                <div className="flex items-baseline gap-2 mb-3">
                  <span className="text-5xl font-bold text-white tracking-tight">{t.price}</span>
                  {t.period && <span className="text-sm text-slate-500">{t.period}</span>}
                </div>
                <p className="text-[13px] text-slate-400 mb-6 leading-relaxed min-h-[40px]">{t.desc}</p>
                <Link
                  href="/signup"
                  className={`block w-full text-center py-3 text-[11px] font-mono tracking-[0.3em] font-bold uppercase transition-all ${
                    t.highlight
                      ? "bg-cyan-400 hover:bg-cyan-300 text-black shadow-[0_0_24px_rgba(0,229,255,0.4)]"
                      : "border border-cyan-400/40 text-cyan-300 hover:bg-cyan-500/10 hover:border-cyan-400/70"
                  }`}
                >
                  {t.cta}
                </Link>
                <ul className="mt-6 space-y-2.5">
                  {t.features.map((f) => (
                    <li key={f} className="flex items-start gap-2.5 text-[12px] text-slate-400">
                      <Check className="w-3.5 h-3.5 text-cyan-400 mt-0.5 shrink-0" />
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </ScrollReveal>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ============================================================
   FAQ
   ============================================================ */
function FAQ() {
  const faqs = [
    { q: "How does AgentShield actually integrate?", a: "One line. You change the base_url in your OpenAI SDK call from api.openai.com to your AgentShield gateway. Every request now flows through the security pipeline. Works with LangChain, LlamaIndex, MCP, or any custom orchestrator." },
    { q: "What happens if the LLM judge is down?", a: "Fail-closed. If the judge can't evaluate a tool call within the timeout, the call is denied. Security is never traded for availability." },
    { q: "Does this add latency?", a: "Under 50ms of overhead on the median request. The inbound scanner is deterministic (regex + unicode checks), PII redaction is Redis-backed, and the judge runs only on tool calls — not on every request." },
    { q: "Where does my data live?", a: "Enterprise tier can be fully self-hosted in your own VPC. Pro tier uses our managed cloud (US-East). Free tier shares the managed cloud with strict per-tenant isolation and 7-day log retention." },
    { q: "How is the audit chain tamper-evident?", a: "Every security event is hashed with SHA-256 and chained to the previous event per tenant. Any modification breaks the chain and is detectable by walking it. Same technique Certificate Transparency uses." },
    { q: "Is this SOC 2 compliant?", a: "The Enterprise tier ships with SOC 2 evidence export. Every blocked attack, every redacted PII value, every judge decision is recorded with a trace ID you can hand to auditors." },
  ];

  return (
    <section id="faq" className="relative py-28 px-6 border-t border-cyan-400/10">
      <div className="max-w-[900px] mx-auto">
        <ScrollReveal>
          <div className="text-center mb-16">
            <div className="inline-flex items-center gap-2 mb-4">
              <span className="w-1 h-1 rounded-full bg-amber-400 shadow-[0_0_8px_rgba(255,184,0,1)]" />
              <span className="text-[10px] font-mono tracking-[0.4em] text-amber-300 uppercase">FAQ</span>
            </div>
            <h2 className="text-4xl md:text-5xl font-bold tracking-tight text-white">
              Questions, answered.
            </h2>
          </div>
        </ScrollReveal>

        <div className="space-y-3">
          {faqs.map((f, i) => (
            <ScrollReveal key={i} delay={i * 50}>
              <div className="bg-black/60 backdrop-blur-xl border border-cyan-400/15 p-6 hover:border-cyan-400/40 transition-all">
                <div className="text-[14px] font-semibold text-white mb-2">{f.q}</div>
                <div className="text-[13px] text-slate-400 leading-relaxed">{f.a}</div>
              </div>
            </ScrollReveal>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ============================================================
   Final CTA
   ============================================================ */
function FinalCTA() {
  return (
    <section className="relative py-28 px-6 border-t border-cyan-400/10 overflow-hidden">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(0,229,255,0.18),transparent_60%)] pointer-events-none" />
      <div className="relative max-w-3xl mx-auto text-center">
        <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold tracking-tight text-white mb-6">
          Ship AI agents.
          <br />
          <span className="text-cyan-400 neon-text">Sleep at night.</span>
        </h2>
        <p className="text-base text-slate-400 mb-10 leading-relaxed">
          Set up your first protected workspace in under 60 seconds. No credit
          card. No sales call. Just drop the gateway URL into your code and
          watch attacks bounce off.
        </p>
        <Link
          href="/signup"
          className="group inline-flex bg-cyan-400 hover:bg-cyan-300 text-black px-8 py-4 text-[12px] font-mono tracking-[0.3em] font-bold uppercase transition-all items-center gap-2 hover:scale-[1.03] shadow-[0_0_50px_rgba(0,229,255,0.6)]"
        >
          Create free workspace
          <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
        </Link>
        <div className="mt-6 text-[10px] font-mono tracking-widest text-slate-600 uppercase">
          No card · 10k free requests / month · Cancel anytime
        </div>
      </div>
    </section>
  );
}

/* ============================================================
   Footer
   ============================================================ */
function Footer() {
  return (
    <footer className="relative border-t border-cyan-400/15 bg-black">
      <div className="max-w-[1400px] mx-auto px-6 py-12">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
          <div className="col-span-2 md:col-span-1">
            <Link href="/" className="flex items-center gap-2 mb-4">
              <div className="w-7 h-7 rounded-sm bg-cyan-400 flex items-center justify-center shadow-[0_0_16px_rgba(0,229,255,0.5)]">
                <ShieldCheck className="w-3.5 h-3.5 text-black" strokeWidth={2.5} />
              </div>
              <span className="text-xs font-bold tracking-[0.2em] text-white">
                AGENT<span className="text-cyan-400">SHIELD</span>
              </span>
            </Link>
            <p className="text-[11px] text-slate-500 leading-relaxed max-w-[220px]">
              Zero-trust security for AI agents. Built for teams shipping agentic systems to production.
            </p>
          </div>
          <div>
            <div className="text-[10px] font-mono tracking-[0.3em] text-cyan-400/60 uppercase mb-3">Product</div>
            <ul className="space-y-2 text-[12px] text-slate-400">
              <li><a href="#features" className="hover:text-cyan-400 transition-colors">Features</a></li>
              <li><a href="#pricing" className="hover:text-cyan-400 transition-colors">Pricing</a></li>
              <li><a href="#how" className="hover:text-cyan-400 transition-colors">How it works</a></li>
              <li><a href="#security" className="hover:text-cyan-400 transition-colors">Security</a></li>
            </ul>
          </div>
          <div>
            <div className="text-[10px] font-mono tracking-[0.3em] text-cyan-400/60 uppercase mb-3">Developers</div>
            <ul className="space-y-2 text-[12px] text-slate-400">
              <li><a href="#" className="hover:text-cyan-400 transition-colors">Documentation</a></li>
              <li><a href="#" className="hover:text-cyan-400 transition-colors">API reference</a></li>
              <li><a href="#" className="hover:text-cyan-400 transition-colors">Status</a></li>
              <li>
                <a href="#" className="hover:text-cyan-400 transition-colors flex items-center gap-1.5">
                  <svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor">
                    <path d="M12 .3a12 12 0 0 0-3.8 23.38c.6.12.83-.26.83-.57L9 21.07c-3.34.72-4.04-1.61-4.04-1.61-.55-1.39-1.34-1.76-1.34-1.76-1.08-.74.09-.73.09-.73 1.2.08 1.83 1.24 1.83 1.24 1.07 1.83 2.8 1.3 3.49 1 .1-.78.42-1.31.76-1.61-2.66-.3-5.47-1.33-5.47-5.93 0-1.31.47-2.38 1.24-3.22-.13-.3-.54-1.52.12-3.18 0 0 1-.32 3.3 1.23a11.5 11.5 0 0 1 6 0c2.3-1.55 3.3-1.23 3.3-1.23.66 1.66.25 2.88.12 3.18.77.84 1.24 1.91 1.24 3.22 0 4.61-2.81 5.63-5.49 5.92.43.37.81 1.1.81 2.22 0 1.61-.01 2.9-.01 3.3 0 .32.22.7.83.57A12 12 0 0 0 12 .3z"/>
                  </svg>
                  GitHub
                </a>
              </li>
            </ul>
          </div>
          <div>
            <div className="text-[10px] font-mono tracking-[0.3em] text-cyan-400/60 uppercase mb-3">Company</div>
            <ul className="space-y-2 text-[12px] text-slate-400">
              <li><a href="#" className="hover:text-cyan-400 transition-colors">About</a></li>
              <li><a href="#" className="hover:text-cyan-400 transition-colors">Security</a></li>
              <li><a href="#" className="hover:text-cyan-400 transition-colors">Privacy</a></li>
              <li><a href="#" className="hover:text-cyan-400 transition-colors">Terms</a></li>
            </ul>
          </div>
        </div>

        <div className="mt-12 pt-6 border-t border-cyan-400/10 flex flex-col md:flex-row items-center justify-between gap-4 text-[10px] font-mono tracking-widest text-slate-600 uppercase">
          <div>© 2026 AgentShield · All rights reserved</div>
          <div className="flex items-center gap-5">
            <span className="flex items-center gap-1.5">
              <span className="w-1 h-1 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_8px_rgba(0,229,255,1)]" />
              All systems operational
            </span>
            <span className="flex items-center gap-1.5"><Server className="w-2.5 h-2.5" /> US-EAST-1</span>
            <span className="flex items-center gap-1.5"><Database className="w-2.5 h-2.5" /> SOC 2 Type II</span>
          </div>
        </div>
      </div>
    </footer>
  );
}

/* ============================================================
   Page
   ============================================================ */
export default function LandingPage() {
  return (
    <main className="relative min-h-screen bg-black text-slate-200 antialiased">
      <LandingBackground />

      {/* Neon grid overlay */}
      <div
        className="fixed inset-0 z-[1] pointer-events-none opacity-[0.08]"
        style={{
          backgroundImage:
            "linear-gradient(rgba(0,229,255,.7) 1px, transparent 1px), linear-gradient(90deg, rgba(0,229,255,.7) 1px, transparent 1px)",
          backgroundSize: "72px 72px",
          maskImage:
            "radial-gradient(ellipse 80% 60% at center, black 30%, transparent 100%)",
          WebkitMaskImage:
            "radial-gradient(ellipse 80% 60% at center, black 30%, transparent 100%)",
        }}
      />

      {/* Ambient gradient wash behind hero */}
      <div className="fixed inset-x-0 top-0 h-screen z-[1] pointer-events-none bg-[radial-gradient(ellipse_at_top,rgba(0,229,255,0.15),transparent_60%)]" />
      <div className="fixed inset-x-0 bottom-0 h-screen z-[1] pointer-events-none bg-[radial-gradient(ellipse_at_bottom,rgba(255,184,0,0.08),transparent_60%)]" />

      {/* Sweeping scan line */}
      <div className="fixed inset-0 z-[2] pointer-events-none overflow-hidden">
        <div
          className="absolute left-0 right-0 h-[1px]"
          style={{
            background:
              "linear-gradient(90deg, transparent, rgba(0,229,255,0.6) 20%, rgba(0,229,255,0.6) 80%, transparent)",
            boxShadow: "0 0 24px rgba(0,229,255,0.5)",
            animation: "scanDown 14s linear infinite",
          }}
        />
      </div>

      <div className="relative z-10">
        <Nav />
        <Hero />
        <TrustBar />
        <Features />
        <HowItWorks />
        <Security />
        <Pricing />
        <FAQ />
        <FinalCTA />
        <Footer />
      </div>
    </main>
  );
}