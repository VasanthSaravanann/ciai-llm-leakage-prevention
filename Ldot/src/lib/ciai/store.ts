import { create } from "zustand";
import { persist } from "zustand/middleware";
import { runPipeline, hashOrigin, type Action, type PipelineResult } from "./pipeline";

export interface AuditLog {
  id: string;
  timestamp: number;
  apiKey: string;
  originHash: string;
  rawPreview: string;
  redactedPrompt: string;
  action: Action;
  triggeredPatterns: string[];
  latencyMs: number;
}

export interface Governance {
  rateLimitPerMin: number;
  enableHSTS: boolean;
  enableXFrame: boolean;
  enableCSP: boolean;
  enableNoSniff: boolean;
  smtpEmail: string;
  alertThreshold: number; // violations
  alertWindowSec: number;
}

interface CiaiState {
  logs: AuditLog[];
  governance: Governance;
  addLog: (entry: { apiKey: string; userPrompt: string; result?: PipelineResult }) => AuditLog;
  clearLogs: () => void;
  seed: () => void;
  setGovernance: (g: Partial<Governance>) => void;
}

const SEED_PROMPTS: Array<{ key: string; text: string }> = [
  { key: "sk_live_alpha", text: "Hi, please summarize Q3 sales for our APAC region." },
  { key: "sk_live_alpha", text: "My Aadhaar is 2345 6789 1012, please file my return." },
  { key: "sk_live_beta", text: "PAN: ABCDE1234F — onboard this vendor." },
  { key: "sk_live_beta", text: "Card 4111 1111 1111 1111 expires next month." },
  { key: "sk_live_gamma", text: "Email me at user@example.com with the report." },
  { key: "sk_live_gamma", text: "My A@dh4ar is 2345.6789.1012 — handle quietly." },
  { key: "sk_live_delta", text: "Translate this please: hello team, lovely meeting." },
  { key: "sk_live_delta", text: "Use key sk_live_AbCdEf0123456789AbCdEf in prod." },
];

export const useCiai = create<CiaiState>()(
  persist(
    (set, get) => ({
      logs: [],
      governance: {
        rateLimitPerMin: 60,
        enableHSTS: true,
        enableXFrame: true,
        enableCSP: true,
        enableNoSniff: true,
        smtpEmail: "security@company.com",
        alertThreshold: 3,
        alertWindowSec: 60,
      },
      addLog: ({ apiKey, userPrompt, result }) => {
        const r = result ?? runPipeline(userPrompt);
        const entry: AuditLog = {
          id: crypto.randomUUID(),
          timestamp: Date.now(),
          apiKey,
          originHash: hashOrigin(apiKey + userPrompt.slice(0, 16)),
          rawPreview: userPrompt.length > 80 ? userPrompt.slice(0, 80) + "…" : userPrompt,
          redactedPrompt: r.redactedPrompt,
          action: r.action,
          triggeredPatterns: r.triggeredPatterns,
          latencyMs: r.latencyMs,
        };
        set({ logs: [entry, ...get().logs].slice(0, 500) });
        return entry;
      },
      clearLogs: () => set({ logs: [] }),
      seed: () => {
        const { addLog, logs } = get();
        if (logs.length > 0) return;
        SEED_PROMPTS.forEach((p) => addLog({ apiKey: p.key, userPrompt: p.text }));
      },
      setGovernance: (g) => set({ governance: { ...get().governance, ...g } }),
    }),
    { name: "ciai-store-v1" },
  ),
);
