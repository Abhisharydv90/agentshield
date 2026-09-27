<div align="center">

<img src="./dashboard/public/logo.svg" alt="AgentShield" width="280" />

# AgentShield

**The zero-trust firewall for AI agents.**

Block prompt injections, redact PII, and enforce policy on every tool call.
Change one line of code. Ship AI agents. Sleep at night.

[![Next.js 16](https://img.shields.io/badge/Next.js-16-black?style=flat-square&logo=next.js)](https://nextjs.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![Postgres](https://img.shields.io/badge/Postgres-16-4169E1?style=flat-square&logo=postgresql)](https://www.postgresql.org)
[![License](https://img.shields.io/badge/license-UNLICENSED-666?style=flat-square)](#license)

[Live Demo](https://agentshield.vercel.app) · [Features](#features) · [Architecture](#architecture) · [Quickstart](#quickstart)

</div>

---

## What it is

AgentShield is a security gateway that sits between AI agents and the LLMs they call.

When your agent sends a prompt to OpenAI, Claude, or Gemini, that request goes through AgentShield first. Every request is scanned. Every response is evaluated. Every tool call is judged.

If the request contains an attack, it never reaches the model.
If the response contains PII, it's redacted before the LLM sees it.
If the tool call looks malicious, it's blocked before execution.

**The whole point: enterprise security teams can deploy agentic AI without losing control of their data.**

---

## Why it exists

Three things break AI agents in production:

1. **Prompt injection** — an attacker hides `ignore all previous instructions` inside an email, a PDF, a RAG document. The agent obeys. Data leaks.
2. **PII leakage** — the agent sends customer emails, SSNs, and API keys to OpenAI. Compliance teams get fired.
3. **Rogue tool calls** — the LLM hallucinates a `DROP TABLE users` and it actually runs.

Every agent gateway on the market either:
- Only does injection detection (missing PII + tool judgment)
- Only does PII redaction (missing injection + tool judgment)
- Costs $50k/year and requires a 6-month procurement cycle

AgentShield does all three, is open-architecture, and integrates in one line.

---

## Quickstart

### Prerequisites

- Node.js ≥ 20
- Python ≥ 3.12
- Postgres ≥ 16 (with `pgvector`)
- Redis ≥ 7
- One LLM API key (Groq, OpenAI, Anthropic, or Google — any OpenAI-compatible provider)

### Local Setup

```bash
git clone https://github.com/YOUR_USERNAME/agentshield.git
cd agentshield

# Backend
python -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m spacy download en_core_web_lg

cp .env.example .env
# Edit .env: DATABASE_URL, REDIS_URL, JUDGE_KEY, UPSTREAM_KEY

alembic upgrade head
uvicorn app.main:app --reload --port 8000

# Frontend (new terminal)
cd dashboard
npm install
npm run dev
```

- **Backend**: http://localhost:8000
- **API docs**: http://localhost:8000/docs
- **Dashboard**: http://localhost:3000

### Try it

1. Open http://localhost:3000/signup
2. Create a workspace — you'll get an API key
3. Point your agent at `http://localhost:8000/v1` with header `X-API-Key: <your key>`
4. Click **Simulate Attack** on the dashboard to fire a real prompt injection through the pipeline

You'll watch it get blocked in real time.

---

## Features

### Inbound Threat Interception

- 3-stage detection: signature regex → unicode smuggling → vector similarity against 847-pattern corpus
- Blocks before the request reaches the LLM
- Zero latency penalty on the clean path

### Zero-Trust PII Redaction

- Presidio-powered NER (emails, phones, cards, SSNs, IBANs, API keys, names)
- Reversible — swapped with HMAC-derived placeholders
- Redis-backed vault with 15-minute TTL
- Rehydration only at the user edge, never into logs

### LLM-as-a-Judge Circuit Breaker

- Deterministic policy engine runs first (fast, free)
- LLM judge runs second (catches context-aware threats)
- Fail-closed by default — any error = deny
- Streaming tool-call buffer reassembles attacks split across SSE chunks

### Observability & Audit

- Tamper-evident hash-chained audit log (SHA-256, per-tenant)
- Live 3D security dashboard with real-time telemetry
- Click any event to see the judge's full reasoning
- CSV export for compliance teams

### Multi-Tenancy

- Per-tenant isolation by API key or session cookie
- Per-tenant hash chains (Tenant A never sees Tenant B's events)
- Per-tenant policies and rate limits

---

## Architecture

```
       User / Agent
            │
            ▼
    ┌──────────────────────┐
    │   AgentShield        │
    │   Gateway            │
    │                      │
    │  1. Inbound Scanner  │  ──►  Block injection (403)
    │  2. PII Vault        │  ──►  Redact sensitive data
    │  3. Upstream LLM     │  ──►  Forward to OpenAI/Groq
    │  4. Outbound Judge   │  ──►  Block malicious tool calls
    │  5. Audit Chain      │  ──►  SHA-256 hash chain
    │                      │
    └──────────┬───────────┘
               │
               ▼
        LLM Provider
        (OpenAI / Anthropic / Groq / Google)
```

Every request goes through all five layers. Each layer can block. The last layer always logs.

---

## Tech Stack

| Layer | Technology | Why |
|---|---|---|
| Proxy | FastAPI + httpx | Async, sub-50ms overhead |
| Injection detection | regex + pgvector | Free deterministic layer first |
| PII redaction | Presidio + spaCy | Industry-standard NER |
| Vault | Redis | Sub-ms reads, native TTL |
| Judge | LiteLLM / google-genai | Provider-agnostic, fail-closed |
| Audit | Postgres 16 + pgvector | ACID + vector search |
| Frontend | Next.js 16 + React 19 | App Router, server components |
| 3D | three.js + @react-three/fiber | Real textures, live data binding |
| Styling | Tailwind CSS v4 | Zero runtime |
| Auth | JWT + Argon2id | Modern, no session store needed |

---

## OWASP LLM Top 10 Coverage

| Risk | Mitigation |
|---|---|
| LLM01 — Prompt Injection | 3-stage inbound scanner |
| LLM02 — Insecure Output Handling | Outbound judge + normalizer |
| LLM06 — Sensitive Info Disclosure | PII vault + redaction |
| LLM07 — Insecure Plugin Design | Policy engine + tool allowlist |
| LLM08 — Excessive Agency | Circuit breaker + step-up approvals |
| LLM09 — Overreliance | Judge confidence scores + reasoning |

---

## Project Structure

```
agentshield/
├── app/                    # FastAPI backend
│   ├── api/               # REST endpoints
│   ├── db/                # Models + Alembic migrations
│   ├── middleware/        # Trace IDs, rate limit, CSRF, auth
│   ├── policy/            # Policy DSL + engine
│   ├── proxy/             # /v1/chat/completions passthrough
│   ├── security/
│   │   ├── injection/     # 3-stage inbound scanner
│   │   ├── judge/         # LLM judge + stream buffer
│   │   └── pii/           # Presidio + Redis vault
│   └── telemetry/         # Metrics, audit chain
│
├── dashboard/             # Next.js frontend
│   ├── app/
│   │   ├── (auth)/        # Login, signup (3D animated)
│   │   ├── dashboard/     # 3D security console
│   │   └── page.tsx       # Landing page
│   └── components/
│       ├── auth/          # Auth UI components
│       ├── auth3d/        # 3D background, arc reactor
│       └── landing/       # Landing page sections
│
├── tests/                 # pytest suite
├── scripts/               # Seed, rotate keys, rechain
└── Dockerfile             # Railway deployment
```

---

## Deployment

**Backend → Railway**

1. Connect GitHub repo
2. Set env vars: `DATABASE_URL`, `REDIS_URL`, `JUDGE_KEY`, `UPSTREAM_KEY`, `SECRET_KEY`, `ENV=prod`
3. Railway detects `Dockerfile` and deploys

**Frontend → Vercel**

1. Import GitHub repo
2. Root directory: `dashboard`
3. Set `NEXT_PUBLIC_BACKEND_URL=https://your-backend.up.railway.app`
4. Deploy

**Database → Neon**

Free Postgres with `pgvector` preinstalled. Run `CREATE EXTENSION IF NOT EXISTS vector;` once.

---

## Status

- ✅ Inbound injection scanner
- ✅ Zero-trust PII vault
- ✅ LLM-as-a-Judge circuit breaker
- ✅ Streaming tool-call reassembly
- ✅ Tamper-evident audit log
- ✅ Multi-tenancy with per-tenant isolation
- ✅ JWT session auth + Argon2id passwords
- ✅ 3D security dashboard
- ✅ Neon Postgres + Upstash Redis
- 🚧 Stripe billing (next)
- 🚧 Webhooks (Slack, PagerDuty)

---

## License

UNLICENSED. All rights reserved.

---

<div align="center">

**Built with a vendetta against prompt injection.**

[agentshield.app](https://agentshield.app) · [Docs](./docs) · [Report a bug](https://github.com/YOUR_USERNAME/agentshield/issues)

</div>