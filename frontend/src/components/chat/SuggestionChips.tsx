import { MagnifyingGlass } from "@phosphor-icons/react";
import type { SuggestionAction } from "../../lib/types";

/**
 * "Did you mean" chips shown when a referenced entity code didn't resolve (e.g.
 * an unknown APT number). Clicking a chip re-runs the query with that name -
 * the backend never auto-substitutes, so the correction is always the user's
 * explicit choice.
 */
/**
 * Rebuild the query for a clicked chip so it keeps the user's ORIGINAL intent
 * ("what mitigates T10557" + T1055 -> "what mitigates T1055"), not a generic
 * "tell me about X". Falls back to a well-formed lookup when the original has no
 * id/code token to swap (never sends a bare token, which the harm gate dislikes).
 */
function buildChipQuery(sourceQuery: string | undefined, suggestion: string): string {
  const parenId = suggestion.match(/\(([^)]+)\)\s*$/);
  const canonical = parenId ? parenId[1] : suggestion;
  if (sourceQuery) {
    const bad =
      sourceQuery.match(/\b[A-Za-z]{1,4}\d{3,}(?:\.\d+)?\b/) ||
      sourceQuery.match(/\b(?:APT|FIN|UNC)\s?-?\d+\b/i);
    if (bad) return sourceQuery.replace(bad[0], canonical);
  }
  return `tell me about ${suggestion}`;
}

export function SuggestionChips({
  suggestions,
  actions,
  sourceQuery,
  onPick,
}: {
  suggestions: string[];
  actions?: SuggestionAction[];
  sourceQuery?: string;
  onPick?: (value: string) => void;
}) {
  const entries =
    actions && actions.length > 0
      ? actions.map((action) => ({ label: action.label, query: action.query }))
      : (suggestions || []).map((label) => ({
          label,
          query: buildChipQuery(sourceQuery, label),
        }));
  if (entries.length === 0) return null;
  return (
    <div className="relative mt-2.5">
      <p className="mb-1.5 font-mono text-[10px] uppercase tracking-wider text-text-dim">
        Did you mean
      </p>
      <div className="flex flex-wrap gap-1.5">
        {entries.map((entry) => (
          <button
            key={`${entry.label}:${entry.query}`}
            type="button"
            // Current APIs provide an exact intent-preserving query. The
            // buildChipQuery fallback keeps older API responses useful by
            // rebuilding a complete lookup instead of sending a bare label.
            onClick={() => onPick?.(entry.query)}
            disabled={!onPick}
            className="inline-flex items-center gap-1 rounded-full border border-cyan/30 bg-cyan/10 px-2.5 py-1 font-mono text-[11px] text-cyan transition-colors hover:border-cyan/60 hover:bg-cyan/20 disabled:cursor-default disabled:opacity-70"
          >
            <MagnifyingGlass size={11} weight="bold" aria-hidden="true" />
            {entry.label}
          </button>
        ))}
      </div>
    </div>
  );
}
