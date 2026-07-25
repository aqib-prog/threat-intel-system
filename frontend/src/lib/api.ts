import { buildMockResponse, MOCK_STATS } from "./mock";
import type { QueryResponse, StatsResponse } from "./types";

// Configurable so builds can target a real deployed backend without a code
// change (and so a CSP connect-src directive can be scoped to one origin
// instead of allowing arbitrary hosts). Falls back to local dev default.
export const API_BASE: string =
  (import.meta.env.VITE_API_BASE as string | undefined)?.replace(/\/+$/, "") ||
  "http://localhost:8000";

// Sent as X-API-Key on the endpoints backend/security/auth.py gates
// (/query, /filters). Not a real secret once built - see the auth caveat in
// backend/api/README.md. Empty string if unset, matching auth-disabled dev.
const API_KEY: string = (import.meta.env.VITE_API_KEY as string | undefined) || "";

function authHeaders(): Record<string, string> {
  return API_KEY ? { "X-API-Key": API_KEY } : {};
}

// Observed real pipeline latency (guardrail + retrieval + rerank + LLM
// generation) ranges from <1s to ~52s depending on query complexity in
// testing - 20s was cutting off real answers and silently falling back to
// mock mid-query. 90s gives headroom above the worst observed case.
const REQUEST_TIMEOUT_MS = 90000;
const HEALTH_TIMEOUT_MS = 3000;
const STATS_TIMEOUT_MS = 5000;

async function withTimeout(ms: number): Promise<{ signal: AbortSignal; cancel: () => void }> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), ms);
  return { signal: controller.signal, cancel: () => clearTimeout(id) };
}

export async function checkHealth(): Promise<boolean> {
  const { signal, cancel } = await withTimeout(HEALTH_TIMEOUT_MS);
  try {
    const res = await fetch(`${API_BASE}/health`, { signal });
    cancel();
    return res.ok;
  } catch {
    cancel();
    return false;
  }
}

export interface RunQueryResult {
  data: QueryResponse;
  isMock: boolean;
}

export async function runQuery(query: string, skipCorrection = false): Promise<RunQueryResult> {
  const { signal, cancel } = await withTimeout(REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(`${API_BASE}/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      // skip_correction is set once the user answers the "did you mean" gate, so
      // the follow-up query is answered directly and never re-offers a gate.
      body: JSON.stringify({ query, skip_correction: skipCorrection }),
      signal,
    });
    cancel();
    if (res.status === 401) {
      // Falls back to mock like any other failure below, but this
      // specifically means VITE_API_KEY doesn't match the backend's
      // API_KEYS - surface it distinctly so it isn't mistaken for the
      // backend simply being offline.
      console.error("API key rejected (401) - check VITE_API_KEY matches the backend's API_KEYS.");
    }
    if (!res.ok) throw new Error(`Backend responded ${res.status}`);
    const data = (await res.json()) as QueryResponse;
    return { data, isMock: false };
  } catch {
    cancel();
    return { data: buildMockResponse(query), isMock: true };
  }
}

export interface RunStatsResult {
  data: StatsResponse;
  isFallback: boolean;
}

/** Live graph counts. Falls back to the last-known snapshot in lib/mock.ts
 * (clearly labeled in the UI) if the backend is unreachable - never
 * fabricates numbers. */
export async function fetchStats(): Promise<RunStatsResult> {
  const { signal, cancel } = await withTimeout(STATS_TIMEOUT_MS);
  try {
    const res = await fetch(`${API_BASE}/stats`, { signal });
    cancel();
    if (!res.ok) throw new Error(`Backend responded ${res.status}`);
    const data = (await res.json()) as StatsResponse;
    return { data, isFallback: false };
  } catch {
    cancel();
    return {
      data: {
        node_count: MOCK_STATS.nodes,
        relationship_count: MOCK_STATS.relationships,
        tactic_count: MOCK_STATS.tactics,
        generated_at: MOCK_STATS.snapshotAt,
        cached: true,
      },
      isFallback: true,
    };
  }
}
