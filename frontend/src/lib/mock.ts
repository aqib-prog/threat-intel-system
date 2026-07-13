import { MAX_RELEVANCE_SCORE, type QueryResponse } from "./types";

const MOCK_ANSWER = (q: string) =>
  `Based on the knowledge graph, the entity you're asking about maps to technique T1078 (Valid Accounts) under tactic TA0006 (Credential Access). Threat actors observed leveraging this technique include APT29 and FIN7, typically paired with platform-specific tooling on Windows and Linux. This is a mock response generated locally because the Graph RAG backend at localhost:8000 is unreachable — start the FastAPI server to get a live, grounded answer for "${q}".`;

export function buildMockResponse(query: string): QueryResponse {
  // node_type values match orchestration/pipeline.py's CASE statement
  // (PascalCase, no separators) so mock and live data render identically.
  // relevance_score is on the same [0, MAX_RELEVANCE_SCORE] scale the
  // reranker actually clips to (retrieval/reranker.py clipped_score) - not
  // a pre-normalized 0-1 fraction.
  const nodes = [
    {
      name: "Valid Accounts",
      external_id: "T1078",
      node_type: "Technique",
      relevance_score: 0.94 * MAX_RELEVANCE_SCORE,
    },
    {
      name: "APT29",
      external_id: "G0016",
      node_type: "Actor",
      relevance_score: 0.88 * MAX_RELEVANCE_SCORE,
    },
    {
      name: "Credential Access",
      external_id: "TA0006",
      node_type: "Tactic",
      relevance_score: 0.81 * MAX_RELEVANCE_SCORE,
    },
    {
      name: "Mimikatz",
      external_id: "S0002",
      node_type: "Malware",
      relevance_score: 0.74 * MAX_RELEVANCE_SCORE,
    },
  ];

  return {
    query,
    response: MOCK_ANSWER(query),
    answer: MOCK_ANSWER(query),
    filters: { mitre_id: "T1078", tactic: "Credential Access" },
    nodes,
    sources: nodes,
    allowed: true,
    guardrail_category: null,
    retrieved_count: nodes.length,
    context_count: nodes.length,
    latency_ms: 420,
  };
}

/**
 * Fallback-only snapshot, shown solely when GET /stats is unreachable and
 * clearly labeled as such in the UI (see Landing.tsx). Last confirmed
 * against the live graph on 2026-07-12 via a direct Cypher count - do not
 * treat as a live figure, and re-verify before reusing if it goes stale.
 */
export const MOCK_STATS = {
  nodes: 4368,
  relationships: 27653,
  tactics: 15,
  snapshotAt: new Date("2026-07-12T00:00:00Z").getTime() / 1000,
};

export const MOCK_MITRE_BADGES = [
  "T1078",
  "TA0006",
  "T1059",
  "T1055",
  "TA0001",
  "T1105",
  "TA0011",
  "T1027",
  "T1036",
  "TA0002",
  "T1082",
  "T1053",
];
