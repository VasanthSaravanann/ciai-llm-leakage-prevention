import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Terminal,
  ArrowRight,
  Sparkles,
  Layers,
  ScanSearch,
  Lock,
  ChevronDown,
  Check,
  Copy,
  Github,
} from "lucide-react";
import { runPipeline } from "@/lib/ciai/pipeline";
import { BrandMark } from "@/components/ciai/BrandMark";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/")({
  component: LandingPage,
  head: () => ({
    meta: [
      { title: "LDOT — Autonomous Prompt Security Layer" },
      {
        name: "description",
        content:
          "LDOT is a zero-GPU AI security proxy that intercepts LLM prompts, redacts PII, and neutralizes evasion attacks before they reach the model.",
      },
      { property: "og:title", content: "LDOT — Autonomous Prompt Security Layer" },
      {
        property: "og:description",
        content:
          "Stop PII leakage and adversarial prompts at the edge. Local-first, zero-GPU, enterprise-ready.",
      },
    ],
  }),
});

function LandingPage() {
  return (
    <div className="relative overflow-hidden">
      <BackgroundGrid />
      <LandingHeader />
      <Hero />
      <ImpactSimulator />
      <Pillars />
      <SetupTerminal />
      <Footer />
    </div>
  );
}

/* ---------------- Header ---------------- */

function LandingHeader() {
  return (
    <header className="relative z-10 mx-auto flex max-w-7xl items-center justify-between px-6 py-5">
      <Link to="/" className="flex items-center gap-2.5">
        <BrandMark size={36} />
        <div>
          <div className="text-sm font-semibold tracking-tight">LDOT</div>
          <div className="text-[10px] uppercase tracking-[0.18em] text-muted-foreground">
            Prompt Security
          </div>
        </div>
      </Link>
      <nav className="hidden items-center gap-7 text-sm text-muted-foreground md:flex">
        <a href="#simulator" className="hover:text-foreground">
          Live Impact
        </a>
        <a href="#pillars" className="hover:text-foreground">
          Architecture
        </a>
        <a href="#setup" className="hover:text-foreground">
          Quickstart
        </a>
        <Link to="/metrics" className="hover:text-foreground">
          Dashboard
        </Link>
      </nav>
      <Link
        to="/metrics"
        className="inline-flex items-center gap-1.5 rounded-md border border-input bg-background px-3 py-1.5 text-xs font-medium hover:bg-accent"
      >
        Open dashboard <ArrowRight className="h-3.5 w-3.5" />
      </Link>
    </header>
  );
}

/* ---------------- Hero ---------------- */

function Hero() {
  return (
    <section className="relative z-10 mx-auto max-w-7xl px-6 pb-20 pt-12 md:pt-20">
      <div className="grid items-center gap-12 lg:grid-cols-[1.1fr,0.9fr]">
        <div className="animate-fade-in">
          <div className="inline-flex items-center gap-2 rounded-full border border-border bg-card/60 px-3 py-1 text-xs text-muted-foreground backdrop-blur">
            <Sparkles className="h-3.5 w-3.5 text-primary" />
            Autonomous Prompt Security Layer · Phase 1 Prototype
          </div>

          <h1 className="mt-6 text-balance text-4xl font-semibold leading-[1.05] tracking-tight md:text-6xl">
            Secure your LLM prompts against{" "}
            <span className="bg-gradient-to-r from-rose-500 via-amber-400 to-emerald-400 bg-clip-text text-transparent">
              PII leakage
            </span>{" "}
            &amp; evasion attacks.
          </h1>

          <p className="mt-5 max-w-xl text-base text-muted-foreground md:text-lg">
            LDOT is a zero-GPU, high-efficiency security proxy that runs locally between your apps
            and any LLM. It normalizes adversarial payloads, masks regional identifiers, and keeps
            your organization's core assets out of public models — in milliseconds.
          </p>

          <div className="mt-8 flex flex-wrap gap-3">
            <Link
              to="/metrics"
              className="group inline-flex items-center gap-2 rounded-md bg-primary px-5 py-2.5 text-sm font-medium text-primary-foreground shadow-sm transition-all hover:shadow-md hover:translate-y-[-1px]"
            >
              Explore Active Dashboard
              <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
            </Link>
            <a
              href="#setup"
              className="inline-flex items-center gap-2 rounded-md border border-input bg-background px-5 py-2.5 text-sm font-medium hover:bg-accent"
            >
              <Terminal className="h-4 w-4" /> Run Local Prototype
            </a>
          </div>

          <dl className="mt-10 grid max-w-md grid-cols-3 gap-6 text-sm">
            {[
              { k: "0", v: "GPU required" },
              { k: "<5 ms", v: "P50 latency" },
              { k: "11+", v: "PII classes" },
            ].map((s) => (
              <div key={s.v}>
                <dt className="text-2xl font-semibold tracking-tight tabular-nums">{s.k}</dt>
                <dd className="mt-1 text-xs text-muted-foreground">{s.v}</dd>
              </div>
            ))}
          </dl>
        </div>

        <HeroVisual />
      </div>
    </section>
  );
}

function HeroVisual() {
  return (
    <div className="relative">
      <div className="absolute inset-0 -z-10 rounded-3xl bg-gradient-to-br from-primary/10 via-emerald-500/5 to-rose-500/10 blur-2xl" />
      <div className="relative rounded-2xl border border-border bg-card/80 p-5 shadow-xl backdrop-blur">
        <div className="flex items-center gap-1.5 border-b border-border pb-3">
          <span className="h-2.5 w-2.5 rounded-full bg-rose-500/70" />
          <span className="h-2.5 w-2.5 rounded-full bg-amber-500/70" />
          <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/70" />
          <span className="ml-3 font-mono text-[11px] text-muted-foreground">
            ldot://proxy/intercept
          </span>
        </div>
        <div className="space-y-3 pt-4 font-mono text-xs">
          <div className="rounded-md bg-muted/40 px-3 py-2">
            <span className="text-muted-foreground">user »</span>{" "}
            <span>“My A@dh4ar is 2345.6789.1012 — handle quietly.”</span>
          </div>
          <FlowArrow />
          <div className="space-y-1.5 rounded-md border border-border bg-background/60 p-3">
            <PipelineTick label="Zero-width chars cleaned" />
            <PipelineTick label="Homoglyphs &amp; leetspeak normalized" delay={120} />
            <PipelineTick label="Token-splits re-joined" delay={240} />
            <PipelineTick label="AADHAAR pattern matched" delay={360} danger />
          </div>
          <FlowArrow />
          <div className="flex items-start gap-3 rounded-md border border-rose-500/30 bg-rose-500/10 p-3 text-rose-700 dark:text-rose-400">
            <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
            <div>
              <div className="font-semibold">403 — Request short-circuited</div>
              <div className="mt-0.5 text-[11px] opacity-80">
                LLM access revoked · logged to audit vault
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function PipelineTick({
  label,
  delay = 0,
  danger,
}: {
  label: string;
  delay?: number;
  danger?: boolean;
}) {
  return (
    <div
      className="flex items-center gap-2 opacity-0 animate-fade-in"
      style={{ animationDelay: `${delay}ms`, animationFillMode: "forwards" }}
    >
      <span
        className={cn(
          "flex h-4 w-4 items-center justify-center rounded-full",
          danger
            ? "bg-rose-500/20 text-rose-600 dark:text-rose-400"
            : "bg-emerald-500/20 text-emerald-600 dark:text-emerald-400",
        )}
      >
        <Check className="h-3 w-3" />
      </span>
      <span dangerouslySetInnerHTML={{ __html: label }} />
    </div>
  );
}

function FlowArrow() {
  return (
    <div className="flex justify-center text-muted-foreground/60">
      <ChevronDown className="h-4 w-4 animate-pulse" />
    </div>
  );
}

/* ---------------- Impact Simulator ---------------- */

const ATTACK_SAMPLES = [
  "My A@dh4ar is 2345.6789.1012 — handle quietly.",
  "PAN: ABCDE1234F for vendor onboarding.",
  "Card 4111 1111 1111 1111 exp 12/29.",
];

function ImpactSimulator() {
  const [sampleIdx, setSampleIdx] = useState(0);
  const sample = ATTACK_SAMPLES[sampleIdx];
  const [typed, setTyped] = useState("");
  const [stepReached, setStepReached] = useState(0);
  const result = useMemo(() => runPipeline(sample), [sample]);

  // typewriter effect
  useEffect(() => {
    setTyped("");
    setStepReached(0);
    let i = 0;
    const t = setInterval(() => {
      i++;
      setTyped(sample.slice(0, i));
      if (i >= sample.length) clearInterval(t);
    }, 28);
    return () => clearInterval(t);
  }, [sample]);

  // pipeline tick reveal
  useEffect(() => {
    if (typed.length < sample.length) return;
    const stepCount = 4;
    let s = 0;
    const t = setInterval(() => {
      s++;
      setStepReached(s);
      if (s >= stepCount) clearInterval(t);
    }, 350);
    return () => clearInterval(t);
  }, [typed, sample]);

  // auto-cycle samples
  useEffect(() => {
    const t = setTimeout(() => setSampleIdx((i) => (i + 1) % ATTACK_SAMPLES.length), 8000);
    return () => clearTimeout(t);
  }, [sampleIdx]);

  const steps = [
    "Zero-width characters stripped",
    "Homoglyphs · leetspeak normalized",
    "Token splits re-joined",
    "Pattern matrix matched",
  ];

  return (
    <section id="simulator" className="relative z-10 border-y border-border bg-card/30 py-20">
      <div className="mx-auto max-w-7xl px-6">
        <SectionHeading
          eyebrow="Live Impact"
          title="Watch a hostile prompt collapse in real time."
          sub="A side-by-side terminal simulation. Adversarial payload in, sanitized — or short-circuited — out."
        />

        <div className="mt-12 grid gap-4 lg:grid-cols-[1fr,auto,1fr]">
          {/* Left: threat input */}
          <Panel label="Threat input" tone="danger">
            <div className="font-mono text-sm leading-relaxed">
              <span className="text-muted-foreground">$ ldot.proxy --intercept</span>
              <div className="mt-2 whitespace-pre-wrap break-words" suppressHydrationWarning>
                {typed}
                <span className="ml-0.5 inline-block h-4 w-1.5 translate-y-0.5 animate-pulse bg-foreground/70" />
              </div>
            </div>
            <div className="mt-4 flex flex-wrap gap-1.5">
              {ATTACK_SAMPLES.map((s, i) => (
                <button
                  key={i}
                  onClick={() => setSampleIdx(i)}
                  className={cn(
                    "rounded border px-2 py-1 text-[11px]",
                    i === sampleIdx
                      ? "border-primary bg-primary/10 text-primary"
                      : "border-border text-muted-foreground hover:text-foreground",
                  )}
                >
                  Attack {i + 1}
                </button>
              ))}
            </div>
          </Panel>

          {/* Middle: pipeline */}
          <div className="flex flex-col items-center justify-center gap-2 px-2">
            <div className="hidden lg:block text-[10px] uppercase tracking-wider text-muted-foreground">
              Pipeline
            </div>
            <div className="flex w-full flex-col gap-2 lg:w-44">
              {steps.map((s, i) => {
                const active = i < stepReached;
                return (
                  <div
                    key={i}
                    className={cn(
                      "flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-xs transition-all",
                      active
                        ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                        : "border-border bg-card text-muted-foreground",
                    )}
                  >
                    <span
                      className={cn(
                        "flex h-4 w-4 items-center justify-center rounded-full text-[10px]",
                        active ? "bg-emerald-500/30" : "bg-muted",
                      )}
                    >
                      {active ? <Check className="h-2.5 w-2.5" /> : i + 1}
                    </span>
                    {s}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right: resolution */}
          <Panel label="Guardrail resolution" tone={result.action === "block" ? "danger" : "ok"}>
            {stepReached < 4 ? (
              <div className="flex h-full items-center justify-center py-10 text-xs text-muted-foreground">
                Awaiting pipeline…
              </div>
            ) : result.action === "block" ? (
              <div className="space-y-3 animate-fade-in">
                <div className="flex items-center gap-2 text-rose-600 dark:text-rose-400">
                  <ShieldAlert className="h-4 w-4" />
                  <span className="text-sm font-semibold">403 Short-Circuited</span>
                </div>
                <div className="rounded-md border border-rose-500/30 bg-rose-500/10 p-3 font-mono text-xs text-rose-700 dark:text-rose-300">
                  LLM access revoked — request never forwarded upstream.
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {result.triggeredPatterns.map((p) => (
                    <span
                      key={p}
                      className="rounded bg-rose-500/15 px-2 py-0.5 font-mono text-[10px] text-rose-700 dark:text-rose-300"
                    >
                      [{p}]
                    </span>
                  ))}
                </div>
              </div>
            ) : (
              <div className="space-y-3 animate-fade-in">
                <div className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400">
                  <ShieldCheck className="h-4 w-4" />
                  <span className="text-sm font-semibold">Sanitized payload</span>
                </div>
                <div className="rounded-md bg-muted/50 p-3 font-mono text-xs leading-relaxed">
                  {renderRedacted(result.redactedPrompt)}
                </div>
              </div>
            )}
          </Panel>
        </div>

        <div className="mt-10 flex justify-center">
          <Link
            to="/simulator"
            className="inline-flex items-center gap-2 rounded-md border border-input bg-background px-4 py-2 text-sm hover:bg-accent"
          >
            Open the full sandbox <ArrowRight className="h-4 w-4" />
          </Link>
        </div>
      </div>
    </section>
  );
}

function Panel({
  label,
  tone,
  children,
}: {
  label: string;
  tone: "ok" | "danger" | "default";
  children: React.ReactNode;
}) {
  const ring = {
    ok: "ring-emerald-500/20",
    danger: "ring-rose-500/20",
    default: "ring-border",
  }[tone];
  return (
    <div className={cn("rounded-xl border border-border bg-card p-5 ring-1", ring)}>
      <div className="mb-3 flex items-center justify-between">
        <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
          {label}
        </span>
      </div>
      {children}
    </div>
  );
}

function renderRedacted(text: string) {
  const parts = text.split(/(\[[A-Z_]+\])/g);
  return parts.map((p, i) =>
    /^\[[A-Z_]+\]$/.test(p) ? (
      <span
        key={i}
        className="mx-0.5 inline-flex items-center rounded bg-amber-500/20 px-1.5 py-0.5 text-[10px] font-semibold text-amber-700 dark:text-amber-300"
      >
        {p}
      </span>
    ) : (
      <span key={i}>{p}</span>
    ),
  );
}

/* ---------------- Pillars ---------------- */

const PILLARS = [
  {
    icon: ScanSearch,
    title: "Anti-Evasion Normalization Pipeline",
    body: "Systematically unmasks base64, leetspeak, homoglyph swaps and space-split injections before signature matching runs. Adversarial prompts have nowhere to hide.",
    accent: "from-violet-500/20 to-violet-500/0",
  },
  {
    icon: Layers,
    title: "Hybrid Match Engine",
    body: "Lightning-fast local regex matrix paired with lightweight NLP fallbacks. Catches regional identifiers (Aadhaar, PAN, GSTIN, UPI) alongside names and organizations.",
    accent: "from-emerald-500/20 to-emerald-500/0",
  },
  {
    icon: Lock,
    title: "Enterprise Hardening & Traceability",
    body: "Built-in audit vault records every transaction with origin hashes, zero-leak response headers, and OWASP-aligned policy toggles you control from the dashboard.",
    accent: "from-rose-500/20 to-rose-500/0",
  },
];

function Pillars() {
  return (
    <section id="pillars" className="relative z-10 mx-auto max-w-7xl px-6 py-20">
      <SectionHeading
        eyebrow="Structural pillars"
        title="Three foundations. One transparent privacy barrier."
        sub="The Phase 1 build order is opinionated — each pillar maps to a measurable security KPI in the dashboard."
      />
      <div className="ldot-stagger mt-12 grid gap-5 md:grid-cols-3">
        {PILLARS.map((p) => (
          <div
            key={p.title}
            className="group relative overflow-hidden rounded-xl border border-border bg-card p-6 transition-all hover:-translate-y-1 hover:shadow-lg"
          >
            <div
              className={cn(
                "absolute inset-x-0 -top-24 h-32 bg-gradient-to-b blur-2xl opacity-60",
                p.accent,
              )}
            />
            <div className="relative">
              <div className="mb-4 inline-flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
                <p.icon className="h-5 w-5" />
              </div>
              <h3 className="text-base font-semibold tracking-tight">{p.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{p.body}</p>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

/* ---------------- Setup Terminal ---------------- */

const TABS: Record<string, { label: string; code: string }> = {
  python: {
    label: "Python",
    code: `pip install -r requirements.txt
python -m spacy download en_core_web_sm
uvicorn proxy.main:app --port 8000`,
  },
  docker: {
    label: "Docker",
    code: `docker pull ldot/proxy:phase1
docker run -p 8000:8000 \\
  -e LDOT_RATE_LIMIT=60 \\
  ldot/proxy:phase1`,
  },
  curl: {
    label: "Test it",
    code: `curl -X POST http://localhost:8000/v1/intercept \\
  -H "Content-Type: application/json" \\
  -d '{"prompt":"My PAN is ABCDE1234F"}'`,
  },
};

function SetupTerminal() {
  const [tab, setTab] = useState<keyof typeof TABS>("python");
  const [copied, setCopied] = useState(false);
  const code = TABS[tab].code;

  function copy() {
    navigator.clipboard?.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1400);
  }

  return (
    <section
      id="setup"
      className="relative z-10 border-t border-border bg-gradient-to-b from-card/30 to-background py-20"
    >
      <div className="mx-auto max-w-5xl px-6">
        <SectionHeading
          eyebrow="15-Minute local run"
          title="From clone to first intercepted prompt — fast."
          sub="No GPU, no cloud account, no telemetry. Drop LDOT in front of any OpenAI-compatible endpoint."
        />

        <div className="mt-10 overflow-hidden rounded-xl border border-border bg-[oklch(0.18_0.02_265)] shadow-xl">
          <div className="flex items-center justify-between border-b border-white/10 px-4 py-2.5">
            <div className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-rose-400/80" />
              <span className="h-2.5 w-2.5 rounded-full bg-amber-400/80" />
              <span className="h-2.5 w-2.5 rounded-full bg-emerald-400/80" />
              <span className="ml-3 font-mono text-[11px] text-white/60">~/ldot · main</span>
            </div>
            <button
              onClick={copy}
              className="inline-flex items-center gap-1.5 rounded border border-white/10 bg-white/5 px-2 py-1 text-[11px] text-white/70 hover:text-white"
            >
              {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
              {copied ? "Copied" : "Copy"}
            </button>
          </div>

          <div className="flex border-b border-white/10">
            {Object.entries(TABS).map(([k, v]) => (
              <button
                key={k}
                onClick={() => setTab(k as keyof typeof TABS)}
                className={cn(
                  "px-4 py-2 text-xs font-medium transition-colors",
                  tab === k
                    ? "border-b-2 border-emerald-400 text-white"
                    : "text-white/50 hover:text-white/80",
                )}
              >
                {v.label}
              </button>
            ))}
          </div>

          <pre className="overflow-x-auto px-5 py-5 font-mono text-[13px] leading-relaxed text-emerald-200">
            {code}
          </pre>
        </div>

        <div className="mt-8 flex flex-wrap justify-center gap-3">
          <Link
            to="/metrics"
            className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
          >
            Skip ahead · open dashboard <ArrowRight className="h-4 w-4" />
          </Link>
          <Link
            to="/simulator"
            className="inline-flex items-center gap-2 rounded-md border border-input bg-background px-4 py-2 text-sm hover:bg-accent"
          >
            Try the simulator
          </Link>
        </div>
      </div>
    </section>
  );
}

/* ---------------- Footer ---------------- */

function Footer() {
  return (
    <footer className="relative z-10 border-t border-border">
      <div className="mx-auto flex max-w-7xl flex-col items-start justify-between gap-4 px-6 py-8 text-xs text-muted-foreground md:flex-row md:items-center">
        <div className="flex items-center gap-2">
          <BrandMark size={20} />
          <span>
            <strong className="text-foreground">LDOT</strong> · Autonomous Prompt Security Layer
          </span>
        </div>
        <div className="flex items-center gap-5">
          <Link to="/metrics" className="hover:text-foreground">
            Dashboard
          </Link>
          <Link to="/simulator" className="hover:text-foreground">
            Sandbox
          </Link>
          <Link to="/governance" className="hover:text-foreground">
            Governance
          </Link>
          <a href="#" className="inline-flex items-center gap-1 hover:text-foreground">
            <Github className="h-3.5 w-3.5" /> Source
          </a>
        </div>
      </div>
    </footer>
  );
}

/* ---------------- Helpers ---------------- */

function SectionHeading({ eyebrow, title, sub }: { eyebrow: string; title: string; sub?: string }) {
  return (
    <div className="mx-auto max-w-2xl text-center">
      <div className="text-[11px] font-semibold uppercase tracking-[0.22em] text-primary/80">
        {eyebrow}
      </div>
      <h2 className="mt-3 text-balance text-3xl font-semibold tracking-tight md:text-4xl">
        {title}
      </h2>
      {sub && <p className="mt-3 text-sm text-muted-foreground md:text-base">{sub}</p>}
    </div>
  );
}

function BackgroundGrid() {
  return (
    <div
      aria-hidden
      className="pointer-events-none absolute inset-0 -z-0"
      style={{
        backgroundImage:
          "radial-gradient(circle at 50% 0%, color-mix(in oklab, var(--color-primary) 10%, transparent), transparent 60%), linear-gradient(var(--color-border) 1px, transparent 1px), linear-gradient(90deg, var(--color-border) 1px, transparent 1px)",
        backgroundSize: "100% 100%, 48px 48px, 48px 48px",
        maskImage: "radial-gradient(ellipse 80% 60% at 50% 0%, black 40%, transparent 90%)",
      }}
    />
  );
}
