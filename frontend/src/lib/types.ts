// retrieval/reranker.py clips relevance_score to this range (clipped_score) -
// it is not a pre-normalized 0-1 fraction.
export const MAX_RELEVANCE_SCORE = 10;

export interface NodeSource {
  name: string;
  external_id: string | null;
  url: string | null;
  node_type: string;
  relevance_score: number | null;
}

export interface StatsResponse {
  node_count: number;
  relationship_count: number;
  tactic_count: number;
  generated_at: number;
  cached: boolean;
}

/** One deterministic technique match from the log-analysis branch, tying a
 * matched line from the user's own pasted log back to the ATT&CK technique
 * it triggered - see backend/log_analysis/analyzer.py. */
export interface LogEvidenceEntry {
  technique_id: string;
  technique_name: string;
  matched_line: string;
  confidence: "high" | "medium" | "low";
}

/** "rag" (default) is the existing question-answering path; "log_analysis"
 * marks a response produced by deterministic raw-log parsing instead of
 * semantic search - see backend/orchestration/pipeline.py's dispatch branch. */
export type AnswerSource = "rag" | "log_analysis";

/** Authoritative category counts computed server-side from the deterministic
 * answer (e.g. { label: "Techniques", count: 67 }). The chart binds to these
 * directly instead of regex-parsing the answer prose. */
export interface AnswerSection {
  label: string;
  count: number;
}

export interface QueryResponse {
  query: string;
  response: string;
  answer: string;
  filters: Record<string, unknown>;
  nodes: NodeSource[];
  sources: NodeSource[];
  allowed: boolean;
  guardrail_category: string | null;
  retrieved_count: number;
  context_count: number;
  latency_ms: number;
  answer_source?: AnswerSource;
  log_evidence?: LogEvidenceEntry[];
  answer_sections?: AnswerSection[];
  /** MITRE ids in `answer` that exist in our graph - only these get citations. */
  grounded_ids?: string[];
}

export type ChatRole = "user" | "assistant";

export interface ChatMessage {
  id: string;
  role: ChatRole;
  text: string;
  createdAt: number;
  filters?: Record<string, unknown>;
  nodes?: NodeSource[];
  allowed?: boolean;
  guardrailCategory?: string | null;
  latencyMs?: number;
  isMock?: boolean;
  pending?: boolean;
  answerSource?: AnswerSource;
  logEvidence?: LogEvidenceEntry[];
  /** Authoritative category counts from the backend; the chart binds to these. */
  sections?: AnswerSection[];
  /** MITRE ids validated to exist in our graph; gates citation rendering. */
  groundedIds?: string[];
}

export type ConnectionState = "checking" | "online" | "offline";
