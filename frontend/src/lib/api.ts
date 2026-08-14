import { MOCK_STATS } from "./mock";
import type {
  QueryRequestError,
  QueryResponse,
  StatsResponse,
} from "./types";

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
  error?: QueryRequestError;
}

class QueryHttpError extends Error {
  readonly status: number;

  constructor(status: number) {
    super(`Backend responded ${status}`);
    this.name = "QueryHttpError";
    this.status = status;
  }
}

function classifyQueryFailure(error: unknown, timedOut: boolean): QueryRequestError {
  if (timedOut) {
    return {
      kind: "timeout",
      title: "Request timed out",
      message:
        "The backend did not finish within 90 seconds. No answer was fabricated. " +
        "The server may still be busy; wait briefly, then retry.",
    };
  }
  if (error instanceof QueryHttpError && error.status === 401) {
    return {
      kind: "unauthorized",
      title: "Authentication failed",
      message: "The backend rejected the API key. Check the frontend and backend API-key configuration.",
    };
  }
  if (error instanceof QueryHttpError) {
    return {
      kind: "backend_error",
      title: "Backend request failed",
      message: `The backend returned HTTP ${error.status}. No answer was generated.`,
    };
  }
  return {
    kind: "unreachable",
    title: "Backend unreachable",
    message: "The query service could not be reached. No answer was generated.",
  };
}

function buildQueryFailureResponse(query: string, failure: QueryRequestError): QueryResponse {
  // This object intentionally contains no ATT&CK claims, IDs, graph nodes, or
  // sources. Transport failures must never look like grounded RAG answers.
  return {
    query,
    response: failure.message,
    answer: failure.message,
    filters: {},
    nodes: [],
    sources: [],
    allowed: false,
    guardrail_category: null,
    retrieved_count: 0,
    context_count: 0,
    latency_ms: 0,
  };
}

export async function runQuery(query: string, skipCorrection = false): Promise<RunQueryResult> {
  const { signal, cancel } = await withTimeout(REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(`${API_BASE}/query`, {
      method: "POST",
      // The session lives in an HttpOnly cookie; without this the browser
      // withholds it and every request 401s despite being signed in.
      credentials: "include",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      // skip_correction is set once the user answers the "did you mean" gate, so
      // the follow-up query is answered directly and never re-offers a gate.
      body: JSON.stringify({ query, skip_correction: skipCorrection }),
      signal,
    });
    if (!res.ok) throw new QueryHttpError(res.status);
    const data = (await res.json()) as QueryResponse;
    return { data, isMock: false };
  } catch (error) {
    const failure = classifyQueryFailure(error, signal.aborted);
    return {
      data: buildQueryFailureResponse(query, failure),
      isMock: false,
      error: failure,
    };
  } finally {
    cancel();
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

// --- Graph explorer -------------------------------------------------------
// Backed by the standalone /graph router, which shares no code path with
// /query. A failure here is contained: the caller renders an inline error in
// the explorer panel and the answer already on screen is untouched.

export interface GraphNodeRef {
  name: string;
  external_id: string;
  node_type: string;
}

export interface GraphGroup {
  relationship: string;
  label: string;
  direction: "in" | "out";
  nodes: GraphNodeRef[];
  truncated: boolean;
}

export interface GraphNeighbors {
  anchor: GraphNodeRef;
  groups: GraphGroup[];
  total: number;
}

export class GraphLookupError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "GraphLookupError";
    this.status = status;
  }
}

export async function fetchGraphNeighbors(
  externalId: string,
  signal?: AbortSignal
): Promise<GraphNeighbors> {
  const res = await fetch(
    `${API_BASE}/graph/neighbors/${encodeURIComponent(externalId)}`,
    { headers: { ...authHeaders() }, credentials: "include", signal }
  );
  if (!res.ok) {
    // The backend sends a human-readable `detail` for 404/422/503; fall back to
    // a generic line so the panel never renders "[object Object]".
    let detail = "Could not load the graph for this node.";
    try {
      const body = await res.json();
      if (typeof body?.detail === "string") detail = body.detail;
    } catch {
      /* non-JSON error body - keep the generic message */
    }
    throw new GraphLookupError(detail, res.status);
  }
  return (await res.json()) as GraphNeighbors;
}
