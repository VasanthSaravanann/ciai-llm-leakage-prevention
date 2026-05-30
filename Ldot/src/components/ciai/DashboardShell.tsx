import { Link, Outlet, useRouterState } from "@tanstack/react-router";
import { Activity, FlaskConical, Settings2, Home } from "lucide-react";
import { BrandMark } from "@/components/ciai/BrandMark";
import { useEffect } from "react";
import { useCiai } from "@/lib/ciai/store";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/", label: "Home", icon: Home },
  { to: "/metrics", label: "Metrics & Logs", icon: Activity },
  { to: "/simulator", label: "Sandbox Simulator", icon: FlaskConical },
  { to: "/governance", label: "Governance", icon: Settings2 },
];

export function DashboardShell() {
  const seed = useCiai((s) => s.seed);
  const path = useRouterState({ select: (s) => s.location.pathname });

  useEffect(() => {
    seed();
  }, [seed]);

  // Landing page renders full-bleed without the dashboard chrome.
  if (path === "/") {
    return (
      <div className="min-h-screen bg-background text-foreground">
        <div key={path} className="ldot-fade-up">
          <Outlet />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-64 flex-col border-r border-border bg-sidebar p-5 lg:flex">
        <div className="mb-8 flex items-center gap-2">
          <BrandMark size={36} />

          <div>
            <div className="text-sm font-semibold tracking-tight">LDOT</div>
            <div className="text-xs text-muted-foreground">AI Security Proxy</div>
          </div>
        </div>
        <nav className="flex flex-col gap-1">
          {NAV.map((n) => {
            const Icon = n.icon;
            const active = path === n.to;
            return (
              <Link
                key={n.to}
                to={n.to}
                className={cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                  active
                    ? "bg-sidebar-accent text-sidebar-accent-foreground"
                    : "text-sidebar-foreground/70 hover:bg-sidebar-accent/60 hover:text-sidebar-foreground",
                )}
              >
                <Icon className="h-4 w-4" />
                {n.label}
              </Link>
            );
          })}
        </nav>
        <div className="mt-auto rounded-md border border-border bg-card p-3 text-xs text-muted-foreground">
          <div className="mb-1 font-medium text-foreground">Phase 1 · Prototype</div>
          Transparent privacy barrier with PII redaction & evasion-resistant pipeline.
        </div>
      </aside>

      <header className="flex h-14 items-center gap-2 border-b border-border bg-card/40 px-4 lg:hidden">
        <BrandMark size={24} />
        <span className="text-sm font-semibold">LDOT</span>
        <nav className="ml-auto flex gap-1">
          {NAV.map((n) => (
            <Link
              key={n.to}
              to={n.to}
              className="rounded px-2 py-1 text-xs text-muted-foreground hover:text-foreground"
              activeProps={{ className: "text-foreground" }}
            >
              {n.label}
            </Link>
          ))}
        </nav>
      </header>

      <main className="lg:pl-64">
        <div key={path} className="mx-auto max-w-7xl p-6 ldot-fade-up">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
