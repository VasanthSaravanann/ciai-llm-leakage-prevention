import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Save, Check } from "lucide-react";
import { useCiai } from "@/lib/ciai/store";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/governance")({
  component: GovernanceView,
  head: () => ({
    meta: [
      { title: "Governance & Alerts — LDOT" },
      {
        name: "description",
        content: "Configure rate limits, hardening headers, and SMTP alert thresholds.",
      },
    ],
  }),
});

function GovernanceView() {
  const governance = useCiai((s) => s.governance);
  const setGovernance = useCiai((s) => s.setGovernance);
  const [saved, setSaved] = useState(false);
  const [local, setLocal] = useState(governance);

  function save() {
    setGovernance(local);
    setSaved(true);
    setTimeout(() => setSaved(false), 1500);
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Proxy Governance</h1>
        <p className="text-sm text-muted-foreground">
          Manage rate limits, hardening headers, and alert routing for the proxy fleet.
        </p>
      </div>

      <div className="ldot-stagger grid gap-4 lg:grid-cols-2">
        <Card title="Rate limiting" description="Throttle requests per API key to mitigate abuse.">
          <label className="flex items-center justify-between">
            <span className="text-sm">Max requests / minute / key</span>
            <span className="text-sm font-semibold tabular-nums">{local.rateLimitPerMin}</span>
          </label>
          <input
            type="range"
            min={10}
            max={600}
            step={10}
            value={local.rateLimitPerMin}
            onChange={(e) => setLocal({ ...local, rateLimitPerMin: Number(e.target.value) })}
            className="mt-2 w-full"
          />
          <div className="mt-1 flex justify-between text-[11px] text-muted-foreground">
            <span>10</span>
            <span>600</span>
          </div>
        </Card>

        <Card
          title="OWASP hardening headers"
          description="Inject recommended security headers on every response."
        >
          <div className="space-y-2">
            <Toggle
              label="Strict-Transport-Security (HSTS)"
              checked={local.enableHSTS}
              onChange={(v) => setLocal({ ...local, enableHSTS: v })}
            />
            <Toggle
              label="X-Frame-Options: DENY"
              checked={local.enableXFrame}
              onChange={(v) => setLocal({ ...local, enableXFrame: v })}
            />
            <Toggle
              label="Content-Security-Policy"
              checked={local.enableCSP}
              onChange={(v) => setLocal({ ...local, enableCSP: v })}
            />
            <Toggle
              label="X-Content-Type-Options: nosniff"
              checked={local.enableNoSniff}
              onChange={(v) => setLocal({ ...local, enableNoSniff: v })}
            />
          </div>
        </Card>

        <Card
          title="SMTP alert routing"
          description="Notify the security team when a key exceeds the violation threshold."
        >
          <div className="space-y-3">
            <div>
              <label className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Destination email
              </label>
              <input
                type="email"
                value={local.smtpEmail}
                onChange={(e) => setLocal({ ...local, smtpEmail: e.target.value })}
                className="mt-1 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Violations
                </label>
                <input
                  type="number"
                  min={1}
                  value={local.alertThreshold}
                  onChange={(e) => setLocal({ ...local, alertThreshold: Number(e.target.value) })}
                  className="mt-1 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                />
              </div>
              <div>
                <label className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Window (seconds)
                </label>
                <input
                  type="number"
                  min={10}
                  value={local.alertWindowSec}
                  onChange={(e) => setLocal({ ...local, alertWindowSec: Number(e.target.value) })}
                  className="mt-1 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                />
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              Trigger an alert when a key generates &gt; {local.alertThreshold} PII violations in
              under {local.alertWindowSec}s.
            </p>
          </div>
        </Card>

        <Card
          title="Policy summary"
          description="Effective configuration applied to the proxy mesh."
        >
          <ul className="space-y-2 text-sm">
            <Row k="Rate limit" v={`${local.rateLimitPerMin} req/min/key`} />
            <Row
              k="Hardening"
              v={
                [
                  local.enableHSTS && "HSTS",
                  local.enableXFrame && "X-Frame",
                  local.enableCSP && "CSP",
                  local.enableNoSniff && "NoSniff",
                ]
                  .filter(Boolean)
                  .join(" · ") || "none"
              }
            />
            <Row k="Alert email" v={local.smtpEmail || "—"} />
            <Row k="Alert rule" v={`>${local.alertThreshold} hits / ${local.alertWindowSec}s`} />
          </ul>
        </Card>
      </div>

      <div className="flex justify-end">
        <button
          onClick={save}
          className={cn(
            "inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90",
            saved && "bg-emerald-600 hover:bg-emerald-600",
          )}
        >
          {saved ? <Check className="h-4 w-4" /> : <Save className="h-4 w-4" />}
          {saved ? "Saved" : "Save policy"}
        </button>
      </div>
    </div>
  );
}

function Card({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <div className="lift rounded-lg border border-border bg-card p-5">
      <h2 className="text-sm font-semibold">{title}</h2>
      <p className="mb-4 text-xs text-muted-foreground">{description}</p>
      {children}
    </div>
  );
}

function Toggle({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="flex cursor-pointer items-center justify-between rounded-md border border-border bg-background px-3 py-2">
      <span className="text-sm">{label}</span>
      <button
        type="button"
        onClick={() => onChange(!checked)}
        className={cn(
          "relative h-5 w-9 rounded-full transition-colors",
          checked ? "bg-primary" : "bg-muted",
        )}
      >
        <span
          className={cn(
            "absolute top-0.5 h-4 w-4 rounded-full bg-background shadow transition-all",
            checked ? "left-[18px]" : "left-0.5",
          )}
        />
      </button>
    </label>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <li className="flex items-center justify-between border-b border-border/60 pb-2 last:border-0 last:pb-0">
      <span className="text-muted-foreground">{k}</span>
      <span className="font-mono text-xs">{v}</span>
    </li>
  );
}
