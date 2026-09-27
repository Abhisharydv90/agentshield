import type { Metadata } from "next";
import Link from "next/link";
import {
  Lock,
  EyeOff,
  Gavel,
  Layers,
  Zap,
  Activity,
  ArrowRight,
  Check,
  Terminal,
  Server,
  Database,
  Globe,
} from "lucide-react";

export const metadata: Metadata = {
  title: "AgentShield · Zero-trust security for AI agents",
  description:
    "Block prompt injections, redact PII, and enforce policy on every tool call. Security infrastructure for teams building agentic systems.",
  openGraph: {
    title: "AgentShield · Zero-trust security for AI agents",
    description:
      "Block prompt injections, redact PII, and enforce policy on every tool call.",
    images: ["/og.svg"],
  },
};

/* ============================================================
   Peak mark — / \ used everywhere as the logo symbol
   ============================================================ */
function PeakMark({ size = 26, stroke = "#ffffff" }: { size?: number; stroke?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" className="shrink-0">
      <g strokeLinecap="round" strokeLinejoin="round" fill="none">
        <path d="M4 34 L20 6 L36 34" stroke={stroke} strokeWidth="2.8" />
      </g>
    </svg>
  );
}

/* ============================================================
   Ambient background — Mercury-style drifting radial glows
   ============================================================ */
function AmbientBackground() {
  return (
    <div className="fixed inset-0 z-0 pointer-events-none overflow-hidden">
      <div className="absolute inset-0 bg-black" />

      {/* Orb A — top left, cyan */}
      <div
        className="drift-a absolute -top-[20%] -left-[10%] w-[70vw] h-[70vw] rounded-full"
        style={{
          background:
            "radial-gradient(circle, rgba(125,211,252,0.35) 0%, rgba(125,211,252,0.15) 30%, transparent 65%)",
          filter: "blur(60px)",
        }}
      />

      {/* Orb B — bottom right, deeper blue */}
      <div
        className="drift-b absolute -bottom-[25%] -right-[15%] w-[80vw] h-[80vw] rounded-full"
        style={{
          background:
            "radial-gradient(circle, rgba(59,130,246,0.28) 0%, rgba(59,130,246,0.12) 35%, transparent 65%)",
          filter: "blur(80px)",
        }}
      />

      {/* Orb C — center, violet */}
      <div
        className="drift-c absolute top-[30%] left-[35%] w-[50vw] h-[50vw] rounded-full"
        style={{
          background:
            "radial-gradient(circle, rgba(139,92,246,0.20) 0%, transparent 60%)",
          filter: "blur(70px)",
        }}
      />

      {/* Subtle grid overlay */}
      <div
        className="absolute inset-0 opacity-[0.04]"
        style={{
          backgroundImage:
            "linear-gradient(rgba(255,255,255,.4) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.4) 1px, transparent 1px)",
          backgroundSize: "80px 80px",
          maskImage:
            "radial-gradient(ellipse 70% 50% at 50% 30%, black 30%, transparent 80%)",
          WebkitMaskImage:
            "radial-gradient(ellipse 70% 50% at 50% 30%, black 30%, transparent 80%)",
        }}
      />

      {/* Soft vignettes — light enough to let glow through */}
      <div className="absolute inset-x-0 top-0 h-[400px] bg-gradient-to-b from-black/40 to-transparent" />
      <div className="absolute inset-x-0 bottom-0 h-[400px] bg-gradient-to-t from-black/60 to-transparent" />
    </div>
  );
}

/* ============================================================
   Nav
   ============================================================ */
function Nav() {
  return (
    <nav className="fixed top-0 left-0 right-0 z-50 border-b border-white/[0.06] bg-black/40 backdrop-blur-2xl">
      <div className="max-w-[1400px] mx-auto px-8 h-16 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-3 group">
          <PeakMark size={26} />
          <span
            className="text-[20px] italic text-white"
            style={{ fontFamily: "Georgia, serif" }}
          >
            AgentShield
          </span>
        </Link>

        <div className="hidden md:flex items-center gap-9 text-[13px] font-mono tracking-wide text-slate-500">
          <a href="#features" className="hover:text-white transition-colors">Product</a>
          <a href="#security" className="hover:text-white transition-colors">Security</a>
          <a href="#how" className="hover:text-white transition-colors">How it works</a>
          <a href="#pricing" className="hover:text-white transition-colors">Pricing</a>
        </div>

        <div className="flex items-center gap-5">
          <Link
            href="/login"
            className="text-[13px] font-mono tracking-wide text-slate-400 hover:text-white transition-colors"
          >
            Sign in
          </Link>
          <Link
            href="/signup"
            className="bg-white text-black px-4 py-2 text-[13px] font-medium rounded-md hover:bg-slate-200 transition-colors"
          >
            Get started
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
    <section className="relative pt-44 pb-32 px-8">
      <div className="relative max-w-[1400px] mx-auto grid grid-cols-1 lg:grid-cols-[1.15fr_0.85fr] gap-20 items-center">
        <div>
          <div className="inline-flex items-center gap-2.5 px-3 py-1.5 border border-white/[0.08] rounded-full mb-10 bg-white/[0.02]">
            <span className="w-1.5 h-1.5 rounded-full bg-[#7dd3fc] ambient-pulse" />
            <span className="text-[11px] font-mono tracking-[0.18em] uppercase text-slate-400">
              Zero-trust for AI agents
            </span>
          </div>

          <h1
            className="text-[68px] md:text-[104px] leading-[0.96] tracking-[-0.035em] text-white mb-10"
            style={{ fontFamily: "Georgia, serif", fontWeight: 400 }}
          >
            Every agent
            <br />
            action,{" "}
            <em className="italic text-[#7dd3fc]">audited.</em>
          </h1>

          <p className="text-[19px] text-slate-400 leading-[1.6] max-w-[540px] mb-12">
            Block prompt injections, redact PII, and enforce policy on every
            tool call. Security infrastructure for teams building agentic
            systems enterprises can trust.
          </p>

          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3 mb-10">
            <Link
              href="/signup"
              className="group bg-white text-black px-7 py-3.5 text-[14px] font-medium rounded-lg hover:bg-slate-200 transition-all flex items-center gap-2"
            >
              Start free
              <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
            </Link>
            <a
              href="#how"
              className="px-7 py-3.5 text-[14px] font-medium rounded-lg border border-white/12 text-slate-200 hover:border-white/25 hover:bg-white/[0.03] transition-all flex items-center gap-2"
            >
              <Terminal className="w-4 h-4" />
              See how it works
            </a>
          </div>

          <p className="text-[12px] font-mono tracking-wide text-slate-600">
            No credit card · 10,000 free requests / month
          </p>
        </div>

        <div className="relative">
          <div className="relative bg-white/[0.025] backdrop-blur-2xl border border-white/[0.08] rounded-2xl p-8 shadow-[0_40px_120px_-30px_rgba(125,211,252,0.2)]">
            <span className="absolute top-0 left-0 w-4 h-4 border-l border-t border-[#7dd3fc]/50" />
            <span className="absolute bottom-0 right-0 w-4 h-4 border-r border-b border-[#7dd3fc]/50" />

            <div className="flex items-center justify-between mb-8">
              <span className="text-[10px] font-mono tracking-[0.22em] uppercase text-slate-500">
                Gateway · Live
              </span>
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-[#7dd3fc] ambient-pulse" />
                <span className="text-[10px] font-mono tracking-[0.22em] uppercase text-[#7dd3fc]">
                  Online
                </span>
              </div>
            </div>

            <StatRow label="Requests · 24h" value="14,892" />
            <StatRow label="Blocked attacks" value="2,741" accent />
            <StatRow label="PII redacted" value="1,203" />
            <StatRow label="Avg latency" value="42 ms" />
            <StatRow label="Uptime · 30d" value="99.98%" />
            <StatRow label="Audit chain" value="Verified" accent />
          </div>
        </div>
      </div>
    </section>
  );
}

function StatRow({
  label,
  value,
  accent,
}: {
  label: string;
  value: string;
  accent?: boolean;
}) {
  return (
    <div className="flex items-center justify-between py-4 border-b border-white/[0.05] last:border-0 last:pb-0">
      <span className="text-[14px] text-slate-500">{label}</span>
      <span
        className={`text-[15px] font-mono tabular-nums ${
          accent ? "text-[#7dd3fc]" : "text-white"
        }`}
      >
        {value}
      </span>
    </div>
  );
}

/* ============================================================
   Trust bar
   ============================================================ */
function TrustBar() {
  const stats = [
    { value: "847", label: "Attack patterns" },
    { value: "Under 50ms", label: "Added latency" },
    { value: "99.98%", label: "Uptime SLA" },
    { value: "SHA-256", label: "Audit chain" },
  ];
  return (
    <section className="relative border-y border-white/[0.06]">
      <div className="max-w-[1400px] mx-auto px-8 py-14 grid grid-cols-2 md:grid-cols-4 gap-10">
        {stats.map((s) => (
          <div key={s.label}>
            <div
              className="text-[38px] text-white tracking-[-0.03em] mb-2"
              style={{ fontFamily: "Georgia, serif" }}
            >
              {s.value}
            </div>
            <div className="text-[11px] font-mono tracking-[0.18em] uppercase text-slate-500">
              {s.label}
            </div>
          </div>
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
    {
      icon: <Lock className="w-[18px] h-[18px]" />,
      title: "Inbound injection scanner",
      desc: "Three-stage detection — signature matching against 847 patterns, unicode smuggling, and semantic vector similarity. Blocks before the model sees it.",
    },
    {
      icon: <EyeOff className="w-[18px] h-[18px]" />,
      title: "Zero-trust PII vault",
      desc: "Detects and swaps emails, SSNs, cards, and API keys before they reach the LLM. Reversible with HMAC placeholders and a 15-minute TTL.",
    },
    {
      icon: <Gavel className="w-[18px] h-[18px]" />,
      title: "LLM-as-a-Judge circuit breaker",
      desc: "Every tool call evaluated against your policy by a secondary LLM judge. Fail-closed by default. Streaming tool-call reassembly included.",
    },
    {
      icon: <Layers className="w-[18px] h-[18px]" />,
      title: "Tamper-evident audit log",
      desc: "Every security event written to a per-tenant SHA-256 hash chain. Modifying any row is cryptographically detectable.",
    },
    {
      icon: <Zap className="w-[18px] h-[18px]" />,
      title: "OpenAI-compatible proxy",
      desc: "Change one line of code. Works with LangChain, LlamaIndex, MCP, or any custom orchestrator. No SDK to learn.",
    },
    {
      icon: <Activity className="w-[18px] h-[18px]" />,
      title: "Real-time telemetry",
      desc: "Live dashboard showing block rates, PII counts, judge decisions, token spend, and latency budgets across every tenant.",
    },
  ];

  return (
    <section id="features" className="relative py-36 px-8">
      <div className="max-w-[1400px] mx-auto">
        <div className="max-w-[760px] mb-24">
          <div className="text-[11px] font-mono tracking-[0.22em] uppercase text-[#7dd3fc] mb-8">
            The stack
          </div>
          <h2
            className="text-[60px] md:text-[80px] leading-[1] tracking-[-0.035em] text-white mb-8"
            style={{ fontFamily: "Georgia, serif" }}
          >
            Four defense layers.
            <br />
            <em className="italic text-slate-500">Zero trust by default.</em>
          </h2>
          <p className="text-[18px] text-slate-400 leading-[1.6]">
            Every request passes through all four gates. Each gate can block.
            The last gate always records.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-x-16 gap-y-16">
          {features.map((f) => (
            <div key={f.title} className="group">
              <div className="w-11 h-11 flex items-center justify-center border border-white/[0.12] text-[#7dd3fc] rounded-lg mb-6 group-hover:border-[#7dd3fc]/50 transition-colors">
                {f.icon}
              </div>
              <h3 className="text-[18px] font-medium text-white mb-3 tracking-[-0.01em]">
                {f.title}
              </h3>
              <p className="text-[14px] text-slate-500 leading-[1.65]">
                {f.desc}
              </p>
            </div>
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
    {
      n: "01",
      title: "Point at the gateway",
      desc: "Change one URL in your agent code. Your agent now talks through AgentShield instead of directly to OpenAI.",
    },
    {
      n: "02",
      title: "Every request scanned",
      desc: "Injection attempts blocked with a 403. PII redacted to reversible tokens. Tool calls buffered and normalized.",
    },
    {
      n: "03",
      title: "Every action judged",
      desc: "When the agent proposes a tool call — SQL, email, API — the circuit breaker evaluates it. Malicious actions never execute.",
    },
    {
      n: "04",
      title: "Everything audited",
      desc: "A hash-chained log records every decision with its reasoning. Compliance teams get proof. Auditors get a receipt.",
    },
  ];

  return (
    <section id="how" className="relative py-36 px-8 border-t border-white/[0.06]">
      <div className="max-w-[1100px] mx-auto">
        <div className="mb-24">
          <div className="text-[11px] font-mono tracking-[0.22em] uppercase text-[#7dd3fc] mb-8">
            How it works
          </div>
          <h2
            className="text-[60px] md:text-[80px] leading-[1] tracking-[-0.035em] text-white"
            style={{ fontFamily: "Georgia, serif" }}
          >
            A firewall in front
            <br />
            of every{" "}
            <em className="italic text-[#7dd3fc]">decision.</em>
          </h2>
        </div>

        <div className="border-t border-white/[0.06]">
          {steps.map((s) => (
            <div
              key={s.n}
              className="grid grid-cols-1 md:grid-cols-[100px_1fr_1.5fr] gap-10 py-12 border-b border-white/[0.06] items-baseline"
            >
              <div
                className="text-[36px] text-slate-600 tabular-nums"
                style={{ fontFamily: "Georgia, serif" }}
              >
                {s.n}
              </div>
              <h3 className="text-[24px] text-white tracking-[-0.015em]">
                {s.title}
              </h3>
              <p className="text-[15px] text-slate-400 leading-[1.65]">
                {s.desc}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ============================================================
   Security — OWASP mapping
   ============================================================ */
function Security() {
  const items = [
    { code: "LLM01", name: "Prompt injection", desc: "Blocked at the gateway before reaching the model." },
    { code: "LLM02", name: "Insecure output handling", desc: "Outbound judge evaluates every tool call." },
    { code: "LLM06", name: "Sensitive info disclosure", desc: "PII redaction with reversible vault and short TTL." },
    { code: "LLM07", name: "Insecure plugin design", desc: "Policy engine + tool allowlist on every call." },
    { code: "LLM08", name: "Excessive agency", desc: "Circuit breaker + human-in-the-loop approvals." },
    { code: "LLM09", name: "Overreliance", desc: "Judge verdicts include confidence and reasoning." },
  ];

  return (
    <section id="security" className="relative py-36 px-8 border-t border-white/[0.06]">
      <div className="max-w-[1400px] mx-auto">
        <div className="max-w-[760px] mb-24">
          <div className="text-[11px] font-mono tracking-[0.22em] uppercase text-[#7dd3fc] mb-8">
            OWASP aligned
          </div>
          <h2
            className="text-[60px] md:text-[80px] leading-[1] tracking-[-0.035em] text-white mb-8"
            style={{ fontFamily: "Georgia, serif" }}
          >
            Built for the threats
            <br />
            that matter in 2026.
          </h2>
          <p className="text-[18px] text-slate-400 leading-[1.6]">
            Every mitigation maps to the OWASP LLM Top 10. Every decision is
            traceable, testable, and exportable.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-x-16 gap-y-12">
          {items.map((item) => (
            <div key={item.code}>
              <div className="flex items-center gap-4 mb-4">
                <span className="text-[11px] font-mono tracking-[0.18em] text-[#7dd3fc]">
                  {item.code}
                </span>
                <span className="flex-1 h-px bg-white/[0.08]" />
              </div>
              <h3 className="text-[18px] text-white mb-2 tracking-[-0.01em]">
                {item.name}
              </h3>
              <p className="text-[14px] text-slate-500 leading-[1.6]">
                {item.desc}
              </p>
            </div>
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
    {
      name: "Free",
      price: "$0",
      period: "forever",
      desc: "For developers exploring AgentShield.",
      features: [
        "10,000 requests / month",
        "Inbound injection scanning",
        "Basic PII redaction",
        "7-day audit log retention",
        "Community support",
      ],
      cta: "Start free",
      highlight: false,
    },
    {
      name: "Pro",
      price: "$99",
      period: "/ month",
      desc: "For teams shipping AI products to production.",
      features: [
        "500,000 requests / month",
        "All security features enabled",
        "LLM-as-a-Judge circuit breaker",
        "90-day audit log retention",
        "Slack + email alerts",
        "Email support, 24h response",
      ],
      cta: "Start 14-day trial",
      highlight: true,
    },
    {
      name: "Enterprise",
      price: "Custom",
      period: "",
      desc: "For teams with compliance and scale requirements.",
      features: [
        "Unlimited requests",
        "Self-hosted or private cloud",
        "SOC 2 evidence export",
        "SSO + audit API",
        "Dedicated solutions engineer",
        "99.99% uptime SLA",
      ],
      cta: "Contact us",
      highlight: false,
    },
  ];

  return (
    <section id="pricing" className="relative py-36 px-8 border-t border-white/[0.06]">
      <div className="max-w-[1400px] mx-auto">
        <div className="max-w-[760px] mb-24">
          <div className="text-[11px] font-mono tracking-[0.22em] uppercase text-[#7dd3fc] mb-8">
            Pricing
          </div>
          <h2
            className="text-[60px] md:text-[80px] leading-[1] tracking-[-0.035em] text-white mb-8"
            style={{ fontFamily: "Georgia, serif" }}
          >
            Simple pricing.
            <br />
            <em className="italic text-slate-500">No per-token surprises.</em>
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {tiers.map((t) => (
            <div
              key={t.name}
              className={`relative p-9 rounded-2xl border ${
                t.highlight
                  ? "border-[#7dd3fc]/40 bg-white/[0.03]"
                  : "border-white/[0.08] bg-white/[0.01]"
              }`}
            >
              {t.highlight && (
                <div className="absolute -top-3 left-9 bg-[#7dd3fc] text-black px-3 py-1 text-[10px] font-mono tracking-[0.18em] uppercase rounded-full font-medium">
                  Most popular
                </div>
              )}

              <div className="text-[12px] font-mono tracking-[0.18em] uppercase text-slate-500 mb-5">
                {t.name}
              </div>
              <div className="flex items-baseline gap-2 mb-5">
                <span
                  className="text-[56px] text-white tracking-[-0.03em] leading-none"
                  style={{ fontFamily: "Georgia, serif" }}
                >
                  {t.price}
                </span>
                {t.period && (
                  <span className="text-[14px] text-slate-500">{t.period}</span>
                )}
              </div>
              <p className="text-[14px] text-slate-400 leading-[1.6] mb-7 min-h-[44px]">
                {t.desc}
              </p>

              <Link
                href="/signup"
                className={`block w-full text-center py-3.5 text-[13px] font-medium rounded-lg transition-colors ${
                  t.highlight
                    ? "bg-white text-black hover:bg-slate-200"
                    : "border border-white/15 text-white hover:bg-white/[0.04]"
                }`}
              >
                {t.cta}
              </Link>

              <ul className="mt-9 space-y-3.5">
                {t.features.map((f) => (
                  <li
                    key={f}
                    className="flex items-start gap-3 text-[13px] text-slate-400"
                  >
                    <Check className="w-[15px] h-[15px] text-[#7dd3fc] mt-0.5 shrink-0" />
                    <span>{f}</span>
                  </li>
                ))}
              </ul>
            </div>
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
    {
      q: "How does AgentShield integrate?",
      a: "One line. Change the base_url in your OpenAI SDK call from api.openai.com to your AgentShield gateway. Works with LangChain, LlamaIndex, MCP, or any custom orchestrator.",
    },
    {
      q: "What happens if the LLM judge is down?",
      a: "Fail-closed. If the judge can't evaluate a tool call within the timeout, the call is denied. Security is never traded for availability.",
    },
    {
      q: "Does this add latency?",
      a: "Under 50ms median overhead. The inbound scanner is deterministic, PII redaction is Redis-backed, and the judge only runs on tool calls — not every request.",
    },
    {
      q: "Where does my data live?",
      a: "Enterprise tier can be fully self-hosted in your own VPC. Pro tier uses our managed cloud with strict per-tenant isolation and 90-day log retention.",
    },
    {
      q: "How is the audit chain tamper-evident?",
      a: "Every event is SHA-256 hashed and chained to the previous event per tenant. Any modification breaks the chain and is detectable by walking it.",
    },
  ];

  return (
    <section id="faq" className="relative py-36 px-8 border-t border-white/[0.06]">
      <div className="max-w-[1000px] mx-auto">
        <div className="mb-20">
          <div className="text-[11px] font-mono tracking-[0.22em] uppercase text-[#7dd3fc] mb-8">
            FAQ
          </div>
          <h2
            className="text-[60px] md:text-[72px] leading-[1.02] tracking-[-0.035em] text-white"
            style={{ fontFamily: "Georgia, serif" }}
          >
            Questions, <em className="italic text-slate-500">answered.</em>
          </h2>
        </div>

        <div className="border-t border-white/[0.06]">
          {faqs.map((f, i) => (
            <div key={i} className="py-9 border-b border-white/[0.06]">
              <div className="text-[18px] text-white mb-3 tracking-[-0.01em]">
                {f.q}
              </div>
              <div className="text-[14px] text-slate-500 leading-[1.7] max-w-[760px]">
                {f.a}
              </div>
            </div>
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
    <section className="relative py-48 px-8 overflow-hidden">
      <div
        className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[80vw] h-[60vh] rounded-full pointer-events-none"
        style={{
          background:
            "radial-gradient(circle, rgba(125,211,252,0.14) 0%, transparent 60%)",
          filter: "blur(80px)",
        }}
      />

      <div className="relative max-w-[900px] mx-auto text-center">
        <h2
          className="text-[64px] md:text-[96px] leading-[0.98] tracking-[-0.035em] text-white mb-10"
          style={{ fontFamily: "Georgia, serif" }}
        >
          Ship AI agents.
          <br />
          <em className="italic text-[#7dd3fc]">Sleep at night.</em>
        </h2>
        <p className="text-[18px] text-slate-400 max-w-[540px] mx-auto mb-14 leading-[1.6]">
          Set up your first protected workspace in under 60 seconds. No credit
          card. No sales call.
        </p>
        <Link
          href="/signup"
          className="inline-flex items-center gap-2 bg-white text-black px-8 py-4 text-[15px] font-medium rounded-lg hover:bg-slate-200 transition-colors"
        >
          Create free workspace
          <ArrowRight className="w-4 h-4" />
        </Link>
        <div className="mt-7 text-[12px] font-mono tracking-wide text-slate-600">
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
    <footer className="relative border-t border-white/[0.06]">
      <div className="max-w-[1400px] mx-auto px-8 py-20">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-14">
          <div className="col-span-2">
            <Link href="/" className="flex items-center gap-3 mb-7">
              <PeakMark size={26} />
              <span
                className="text-[19px] italic text-white"
                style={{ fontFamily: "Georgia, serif" }}
              >
                AgentShield
              </span>
            </Link>
            <p className="text-[13px] text-slate-500 leading-[1.7] max-w-[320px] mb-6">
              Zero-trust security for AI agents. Built for teams shipping
              agentic systems to production.
            </p>
            <div className="flex items-center gap-2 text-[11px] font-mono tracking-wide text-slate-600">
              <span className="w-1.5 h-1.5 rounded-full bg-[#7dd3fc] ambient-pulse" />
              All systems operational
            </div>
          </div>

          <div>
            <div className="text-[11px] font-mono tracking-[0.18em] uppercase text-slate-500 mb-5">
              Product
            </div>
            <ul className="space-y-3.5 text-[13px] text-slate-400">
              <li><a href="#features" className="hover:text-white transition-colors">Features</a></li>
              <li><a href="#pricing" className="hover:text-white transition-colors">Pricing</a></li>
              <li><a href="#how" className="hover:text-white transition-colors">How it works</a></li>
              <li><a href="#security" className="hover:text-white transition-colors">Security</a></li>
            </ul>
          </div>

          <div>
            <div className="text-[11px] font-mono tracking-[0.18em] uppercase text-slate-500 mb-5">
              Developers
            </div>
            <ul className="space-y-3.5 text-[13px] text-slate-400">
              <li><a href="#" className="hover:text-white transition-colors">Documentation</a></li>
              <li><a href="#" className="hover:text-white transition-colors">API reference</a></li>
              <li><a href="#" className="hover:text-white transition-colors">Status</a></li>
              <li>
                <a
                  href="https://github.com/Abhisharydv90/agentshield"
                  className="hover:text-white transition-colors"
                >
                  GitHub
                </a>
              </li>
            </ul>
          </div>

          <div>
            <div className="text-[11px] font-mono tracking-[0.18em] uppercase text-slate-500 mb-5">
              Company
            </div>
            <ul className="space-y-3.5 text-[13px] text-slate-400">
              <li><a href="#" className="hover:text-white transition-colors">About</a></li>
              <li><a href="#" className="hover:text-white transition-colors">Security</a></li>
              <li><a href="#" className="hover:text-white transition-colors">Privacy</a></li>
              <li><a href="#" className="hover:text-white transition-colors">Terms</a></li>
            </ul>
          </div>
        </div>

        <div className="mt-20 pt-10 border-t border-white/[0.06] flex flex-col md:flex-row items-center justify-between gap-5 text-[11px] font-mono tracking-wide text-slate-600 uppercase">
          <div>© 2026 AgentShield · All rights reserved</div>
          <div className="flex items-center gap-7">
            <span className="flex items-center gap-1.5">
              <Server className="w-3 h-3" /> US-EAST-1
            </span>
            <span className="flex items-center gap-1.5">
              <Database className="w-3 h-3" /> SOC 2 TYPE II
            </span>
            <span className="flex items-center gap-1.5">
              <Globe className="w-3 h-3" /> GLOBAL EDGE
            </span>
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
      <AmbientBackground />
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