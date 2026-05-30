import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Activity, ShieldAlert, ShieldCheck, Eraser, Timer, Download, Trash2 } from "lucide-react";
import { useCiai, type AuditLog } from "@/lib/ciai/store";
import { getCiaiDashboardUrl, isCiaiApiConfigured } from "@/lib/ciai/api";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/metrics")({
  component: MetricsView,
  head: () => ({
    meta: [
      { title: "Metrics & Audit Logs — LDOT" },
      {
        name: "description",
        content: "Real-time security metrics and audit trail for LDOT AI proxy traffic.",
      },
    ],
  }),
});

function MetricsView() {
  const logs = useCiai((s) => s.logs);
  const clearLogs = useCiai((s) => s.clearLogs);

  const [apiKeyFilter, setApiKeyFilter] = useState("all");
  const [actionFilter, setActionFilter] = useState<"all" | AuditLog["action"]>("all");
  const [patternFilter, setPatternFilter] = useState("all");
  const [hours, setHours] = useState(24);

  const apiKeys = useMemo(() => Array.from(new Set(logs.map((l) => l.apiKey))), [logs]);
  const patterns = useMemo(
    () => Array.from(new Set(logs.flatMap((l) => l.triggeredPatterns))),
    [logs],
  );

  const filtered = useMemo(() => {
    const cutoff = Date.now() - hours * 3600 * 1000;
    return logs.filter((l) => {
      if (l.timestamp < cutoff) return false;
      if (apiKeyFilter !== "all" && l.apiKey !== apiKeyFilter) return false;
      if (actionFilter !== "all" && l.action !== actionFilter) return false;
      if (patternFilter !== "all" && !l.triggeredPatterns.includes(patternFilter)) return false;
      return true;
    });
  }, [logs, apiKeyFilter, actionFilter, patternFilter, hours]);

  const metrics = useMemo(() => {
    const total = filtered.length;
    const blocked = filtered.filter((l) => l.action === "block").length;
    const redacted = filtered.filter((l) => l.action === "redact").length;
    const tokens = filtered.reduce((acc, l) => acc + l.triggeredPatterns.length, 0);
    const latencies = filtered.map((l) => l.latencyMs).sort((a, b) => a - b);
    const median = latencies.length ? latencies[Math.floor(latencies.length / 2)] : 0;
    const health = total === 0 ? 100 : Math.max(0, 100 - Math.round((blocked / total) * 100));
    return { total, blocked, redacted, tokens, median, health };
  }, [filtered]);

  function exportCSV() {
    const header = [
      "timestamp",
      "api_key",
      "origin_hash",
      "raw_preview",
      "redacted_prompt",
      "action",
      "patterns",
      "latency_ms",
    ].join(",");
    const rows = filtered.map((l) =>
      [
        new Date(l.timestamp).toISOString(),
        l.apiKey,
        l.originHash,
        JSON.stringify(l.rawPreview),
        JSON.stringify(l.redactedPrompt),
        l.action,
        l.triggeredPatterns.join("|"),
        l.latencyMs,
      ].join(","),
    );
    const blob = new Blob([header + "\n" + rows.join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ciai-audit-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Security Metrics</h1>
        <p className="text-sm text-muted-foreground">
          Live overview of intercepted LLM traffic, PII enforcement, and pipeline latency.
        </p>
        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          <span className="rounded-full bg-muted px-2.5 py-1 font-medium text-foreground">
            Local audit store
          </span>
          <span>
            {isCiaiApiConfigured() ? "CIAI backend sync enabled" : "CIAI backend sync disabled"}
          </span>
          <a
            href={getCiaiDashboardUrl()}
            target="_blank"
            rel="noreferrer"
            className="rounded-full border border-input bg-background px-2.5 py-1 hover:bg-accent hover:text-foreground"
          >
            Open backend dashboard
          </a>
        </div>
      </div>

      <div className="ldot-stagger grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-5">
        <MetricCard
          label="Total Requests"
          value={metrics.total.toLocaleString()}
          icon={Activity}
          tone="default"
        />
        <MetricCard
          label="Blocked"
          value={metrics.blocked.toLocaleString()}
          icon={ShieldAlert}
          tone="danger"
        />
        <MetricCard
          label="Redacted Tokens"
          value={metrics.tokens.toLocaleString()}
          icon={Eraser}
          tone="warn"
        />
        <MetricCard
          label="Median Latency"
          value={`${metrics.median.toFixed(1)} ms`}
          icon={Timer}
          tone="default"
        />
        <MetricCard
          label="System Health"
          value={`${metrics.health}%`}
          icon={ShieldCheck}
          tone="ok"
        />
      </div>

      <div className="rounded-lg border border-border bg-card">
        <div className="flex flex-wrap items-end gap-3 border-b border-border p-4">
          <Field label="Window">
            <select
              value={hours}
              onChange={(e) => setHours(Number(e.target.value))}
              className="rounded-md border border-input bg-background px-2 py-1.5 text-sm"
            >
              <option value={1}>Last hour</option>
              <option value={24}>Last 24h</option>
              <option value={168}>Last 7 days</option>
              <option value={8760}>All time</option>
            </select>
          </Field>
          <Field label="API key">
            <select
              value={apiKeyFilter}
              onChange={(e) => setApiKeyFilter(e.target.value)}
              className="rounded-md border border-input bg-background px-2 py-1.5 text-sm"
            >
              <option value="all">All keys</option>
              {apiKeys.map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Action">
            <select
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value as typeof actionFilter)}
              className="rounded-md border border-input bg-background px-2 py-1.5 text-sm"
            >
              <option value="all">All actions</option>
              <option value="allow">Passed</option>
              <option value="redact">Redacted</option>
              <option value="block">Blocked</option>
            </select>
          </Field>
          <Field label="Pattern">
            <select
              value={patternFilter}
              onChange={(e) => setPatternFilter(e.target.value)}
              className="rounded-md border border-input bg-background px-2 py-1.5 text-sm"
            >
              <option value="all">All patterns</option>
              {patterns.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </Field>
          <div className="ml-auto flex gap-2">
            <button
              onClick={exportCSV}
              className="inline-flex items-center gap-2 rounded-md border border-input bg-background px-3 py-1.5 text-sm hover:bg-accent"
            >
              <Download className="h-4 w-4" /> Export CSV
            </button>
            <button
              onClick={clearLogs}
              className="inline-flex items-center gap-2 rounded-md border border-input bg-background px-3 py-1.5 text-sm text-muted-foreground hover:bg-accent"
            >
              <Trash2 className="h-4 w-4" /> Clear
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-left text-xs uppercase tracking-wide text-muted-foreground">
              <tr>
                <th className="px-4 py-2.5">Time</th>
                <th className="px-4 py-2.5">API Key</th>
                <th className="px-4 py-2.5">Origin</th>
                <th className="px-4 py-2.5">Prompt (redacted)</th>
                <th className="px-4 py-2.5">Patterns</th>
                <th className="px-4 py-2.5">Action</th>
                <th className="px-4 py-2.5 text-right">Latency</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-10 text-center text-muted-foreground">
                    No audit records in this window.
                  </td>
                </tr>
              )}
              {filtered.map((l) => (
                <tr
                  key={l.id}
                  className="border-t border-border transition-colors hover:bg-muted/30"
                >
                  <td className="whitespace-nowrap px-4 py-2.5 text-muted-foreground">
                    {new Date(l.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="whitespace-nowrap px-4 py-2.5 font-mono text-xs">{l.apiKey}</td>
                  <td className="whitespace-nowrap px-4 py-2.5 font-mono text-xs text-muted-foreground">
                    {l.originHash}
                  </td>
                  <td className="max-w-md px-4 py-2.5">
                    <div className="truncate font-mono text-xs">{l.redactedPrompt}</div>
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex flex-wrap gap-1">
                      {l.triggeredPatterns.map((p) => (
                        <span
                          key={p}
                          className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground"
                        >
                          {p}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <ActionBadge action={l.action} />
                  </td>
                  <td className="whitespace-nowrap px-4 py-2.5 text-right tabular-nums text-muted-foreground">
                    {l.latencyMs.toFixed(1)} ms
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function MetricCard({
  label,
  value,
  icon: Icon,
  tone,
}: {
  label: string;
  value: string;
  icon: React.ComponentType<{ className?: string }>;
  tone: "default" | "ok" | "warn" | "danger";
}) {
  const toneClass = {
    default: "text-primary bg-primary/10",
    ok: "text-emerald-600 bg-emerald-500/10 dark:text-emerald-400",
    warn: "text-amber-600 bg-amber-500/10 dark:text-amber-400",
    danger: "text-rose-600 bg-rose-500/10 dark:text-rose-400",
  }[tone];
  return (
    <div className="lift rounded-lg border border-border bg-card p-4">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          {label}
        </span>
        <span className={cn("flex h-7 w-7 items-center justify-center rounded-md", toneClass)}>
          <Icon className="h-4 w-4" />
        </span>
      </div>
      <div className="mt-2 text-2xl font-semibold tabular-nums">{value}</div>
    </div>
  );
}

function ActionBadge({ action }: { action: AuditLog["action"] }) {
  const cls = {
    allow: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 ring-emerald-500/30",
    redact: "bg-amber-500/15 text-amber-700 dark:text-amber-400 ring-amber-500/30",
    block: "bg-rose-500/15 text-rose-700 dark:text-rose-400 ring-rose-500/30",
  }[action];
  const label = { allow: "Passed", redact: "Redacted", block: "Blocked" }[action];
  return (
    <span className={cn("rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", cls)}>
      {label}
    </span>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
        {label}
      </span>
      {children}
    </label>
  );
}
