import { type PipelineResult } from "./pipeline";

const DEV_API_BASE = "http://localhost:8000";
const DEFAULT_API_KEY = "ciai-dev-key";

export interface DetectResponse {
  detections: string[];
  block: boolean;
  redact: boolean;
  redacted_text: string;
  severity: string;
}

export interface LogRequest {
  user_id: string;
  redacted_prompt: string;
  detection_types: string[];
  action: string;
  severity: string;
  llm_response_redacted?: string | null;
}

function trimTrailingSlash(value: string) {
  return value.replace(/\/+$/, "");
}

export function getCiaiApiBase() {
  const configured = (import.meta.env.VITE_CIAI_API_BASE as string | undefined)?.trim() || "";
  const fallback = import.meta.env.DEV ? DEV_API_BASE : "";
  return trimTrailingSlash(configured || fallback);
}

export function getCiaiApiKey() {
  return (import.meta.env.VITE_CIAI_API_KEY as string | undefined)?.trim() || DEFAULT_API_KEY;
}

export function getCiaiDashboardUrl() {
  return `${getCiaiApiBase()}/dashboard`;
}

export function isCiaiApiConfigured() {
  const configured = (import.meta.env.VITE_CIAI_API_BASE as string | undefined)?.trim() || "";
  return Boolean(configured || import.meta.env.DEV);
}

export async function detectSensitiveText(text: string, apiKey?: string): Promise<DetectResponse> {
  const response = await fetch(`${getCiaiApiBase()}/detect`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-KEY": apiKey?.trim() || getCiaiApiKey(),
    },
    body: JSON.stringify({ text }),
  });

  if (!response.ok) {
    throw new Error(`CIAI /detect failed with ${response.status}`);
  }

  return (await response.json()) as DetectResponse;
}

export async function logAuditEvent(payload: LogRequest, apiKey?: string) {
  const response = await fetch(`${getCiaiApiBase()}/log`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-KEY": apiKey?.trim() || getCiaiApiKey(),
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(`CIAI /log failed with ${response.status}`);
  }

  return response.json() as Promise<{ status: string; id?: number | null }>;
}

export async function fetchCiaiHealth() {
  const response = await fetch(`${getCiaiApiBase()}/health`, {
    headers: { "X-API-KEY": getCiaiApiKey() },
  });

  return response.ok;
}

export function toLivePipelineResult(
  localResult: PipelineResult,
  detected: DetectResponse,
  latencyMs: number,
): PipelineResult {
  return {
    ...localResult,
    action: detected.block ? "block" : detected.redact ? "redact" : "allow",
    redactedPrompt: detected.redacted_text,
    triggeredPatterns: detected.detections,
    latencyMs,
  };
}
