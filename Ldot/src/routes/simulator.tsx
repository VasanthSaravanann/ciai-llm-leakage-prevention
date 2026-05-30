import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { Play, ChevronDown, Wand2, ShieldX } from "lucide-react";
import { runPipeline, type PipelineResult } from "@/lib/ciai/pipeline";
import { useCiai } from "@/lib/ciai/store";
import {
  detectSensitiveText,
  fetchCiaiHealth,
  getCiaiDashboardUrl,
  getCiaiApiKey,
  isCiaiApiConfigured,
  logAuditEvent,
  toLivePipelineResult,
} from "@/lib/ciai/api";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/simulator")({
  component: SimulatorView,
  head: () => ({
    meta: [
      { title: "Sandbox Simulator — LDOT" },
      {
        name: "description",
        content: "Test obfuscated prompts against the evasion-resistant pipeline.",
      },
    ],
  }),
});

const SAMPLES = [
  "My Aadhaar is 2345 6789 1012 — file my return.",
  "My A@dh4ar is 2345.6789.1012 please be discreet.",
  "PAN: ABCDE1234F for vendor onboarding.",
  "Card 4111 1111 1111 1111 exp 12/29.",
  "Decode this: " +
    (typeof btoa !== "undefined" ? btoa("My pan is ABCDE1234F") : "TXkgcGFuIGlzIEFCQ0RFMTIzNEY="),
];

function SimulatorView() {
  const [input, setInput] = useState(SAMPLES[1]);
  const [apiKey, setApiKey] = useState(getCiaiApiKey());
  const [openStep, setOpenStep] = useState<number | null>(0);
  const addLog = useCiai((s) => s.addLog);
  const [lastLogged, setLastLogged] = useState<string | null>(null);
  const [liveResult, setLiveResult] = useState<PipelineResult | null>(null);
  const [connectionState, setConnectionState] = useState<"checking" | "connected" | "offline">(
    "checking",
  );
  const [submitStatus, setSubmitStatus] = useState<string>("");

  const localResult: PipelineResult = useMemo(() => runPipeline(input), [input]);

  useEffect(() => {
    let cancelled = false;
    if (!isCiaiApiConfigured()) {
      setConnectionState("offline");
      return () => {
        cancelled = true;
      };
    }

    fetchCiaiHealth()
      .then((ok) => {
        if (!cancelled) {
          setConnectionState(ok ? "connected" : "offline");
        }
      })
      .catch(() => {
        if (!cancelled) {
          setConnectionState("offline");
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  async function submit() {
    const started = performance.now();
    let resolved = localResult;

    try {
      const detected = await detectSensitiveText(input, apiKey);
      const latencyMs = +(performance.now() - started).toFixed(2);
      resolved = toLivePipelineResult(localResult, detected, latencyMs);
      await logAuditEvent(
        {
          user_id: "ldot-web",
          redacted_prompt: detected.redacted_text,
          detection_types: detected.detections,
          action: detected.block ? "block" : detected.redact ? "redact" : "allow",
          severity: detected.severity,
        },
        apiKey,
      );
      setSubmitStatus("Synced to CIAI API");
      setConnectionState("connected");
    } catch {
      setSubmitStatus("CIAI API unavailable, using local fallback");
      setConnectionState("offline");
    }

    setLiveResult(resolved);
    const e = addLog({ apiKey, userPrompt: input, result: resolved });
    setLastLogged(e.id);
    setTimeout(() => setLastLogged(null), 1500);
  }

  const result = liveResult ?? localResult;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Sandbox Simulator</h1>
        <p className="text-sm text-muted-foreground">
          Inspect how the proxy normalizes adversarial payloads before pattern matching.
        </p>
        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
          <span
            className={cn(
              "rounded-full px-2.5 py-1 font-medium",
              connectionState === "connected"
                ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400"
                : "bg-muted text-muted-foreground",
            )}
          >
            CIAI API{" "}
            {connectionState === "connected"
              ? "connected"
              : connectionState === "checking"
                ? "checking"
                : "offline"}
          </span>
          <a
            href={getCiaiDashboardUrl()}
            target="_blank"
            rel="noreferrer"
            className="rounded-full border border-input bg-background px-2.5 py-1 text-muted-foreground hover:bg-accent hover:text-foreground"
          >
            Open CIAI dashboard
          </a>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold">Raw prompt</h2>
            <div className="flex items-center gap-2">
              <input
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                className="rounded-md border border-input bg-background px-2 py-1 font-mono text-xs"
                placeholder="api key"
              />
              <button
                onClick={submit}
                className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90"
              >
                <Play className="h-3.5 w-3.5" /> Submit to proxy
              </button>
            </div>
          </div>
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            rows={10}
            spellCheck={false}
            className="w-full resize-none rounded-md border border-input bg-background p-3 font-mono text-sm outline-none focus:ring-2 focus:ring-ring"
          />
          <div className="mt-3">
            <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
              Try a sample
            </div>
            <div className="flex flex-wrap gap-1.5">
              {SAMPLES.map((s, i) => (
                <button
                  key={i}
                  onClick={() => setInput(s)}
                  className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
                >
                  <Wand2 className="h-3 w-3" /> Sample {i + 1}
                </button>
              ))}
            </div>
          </div>
          {lastLogged && (
            <div className="mt-3 rounded-md bg-emerald-500/10 px-3 py-2 text-xs text-emerald-700 dark:text-emerald-400">
              Logged to audit trail · view it on the Metrics page.
            </div>
          )}
          {submitStatus && (
            <div className="mt-2 rounded-md border border-border bg-muted/30 px-3 py-2 text-xs text-muted-foreground">
              {submitStatus}
            </div>
          )}
        </div>

        <div className="rounded-lg border border-border bg-card p-4">
          <h2 className="mb-3 text-sm font-semibold">Pipeline trace</h2>
          <div className="space-y-1.5">
            {result.steps.map((step, i) => (
              <div key={i} className="rounded-md border border-border">
                <button
                  onClick={() => setOpenStep(openStep === i ? null : i)}
                  className="flex w-full items-center justify-between px-3 py-2 text-left"
                >
                  <div className="flex items-center gap-2">
                    <span className="flex h-5 w-5 items-center justify-center rounded-full bg-primary/10 text-[11px] font-medium text-primary">
                      {i + 1}
                    </span>
                    <span className="text-sm font-medium">{step.name}</span>
                    {step.note && (
                      <span className="text-xs text-muted-foreground">· {step.note}</span>
                    )}
                  </div>
                  <ChevronDown
                    className={cn(
                      "h-4 w-4 text-muted-foreground transition-transform",
                      openStep === i && "rotate-180",
                    )}
                  />
                </button>
                {openStep === i && (
                  <pre className="overflow-x-auto border-t border-border bg-muted/30 px-3 py-2 font-mono text-xs">
                    {step.output || <span className="text-muted-foreground">(empty)</span>}
                  </pre>
                )}
              </div>
            ))}
          </div>

          <div className="mt-4 border-t border-border pt-4">
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Downstream payload
            </h3>
            {result.action === "block" ? (
              <div className="flex items-start gap-3 rounded-md border border-rose-500/30 bg-rose-500/10 p-3 text-rose-700 dark:text-rose-400">
                <ShieldX className="mt-0.5 h-5 w-5" />
                <div>
                  <div className="text-sm font-semibold">403 — Access Denied</div>
                  <div className="mt-1 text-xs">
                    Critical PII detected ({result.triggeredPatterns.join(", ")}). Request was
                    short-circuited and never forwarded to the upstream model.
                  </div>
                </div>
              </div>
            ) : (
              <div className="rounded-md bg-muted/40 p-3 font-mono text-sm">
                {renderRedacted(result.redactedPrompt)}
              </div>
            )}
            <div className="mt-2 flex flex-wrap gap-3 text-xs text-muted-foreground">
              <span>
                Action: <strong className="text-foreground">{result.action}</strong>
              </span>
              <span>
                Patterns:{" "}
                <strong className="text-foreground">
                  {result.triggeredPatterns.join(", ") || "none"}
                </strong>
              </span>
              <span>
                Latency:{" "}
                <strong className="text-foreground" suppressHydrationWarning>
                  {result.latencyMs.toFixed(2)} ms
                </strong>
              </span>
              {result.base64Decoded && result.base64Decoded.length > 0 && (
                <span>
                  Base64 layers:{" "}
                  <strong className="text-foreground">{result.base64Decoded.length}</strong>
                </span>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function renderRedacted(text: string) {
  const parts = text.split(/(\[[A-Z_]+\])/g);
  return parts.map((p, i) =>
    /^\[[A-Z_]+\]$/.test(p) ? (
      <span
        key={i}
        className="mx-0.5 inline-flex items-center rounded bg-amber-500/20 px-1.5 py-0.5 text-[11px] font-semibold text-amber-700 dark:text-amber-300"
      >
        {p}
      </span>
    ) : (
      <span key={i}>{p}</span>
    ),
  );
}
