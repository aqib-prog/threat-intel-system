import { useMemo } from "react";
import { motion } from "framer-motion";
import { clsx } from "clsx";
import { ShieldWarning, Terminal } from "@phosphor-icons/react";
import type { AnswerSegment } from "../../lib/types";
import { MarkdownMessage } from "./MarkdownMessage";
import { AnswerVisualization } from "./AnswerVisualization";
import { SingleCategoryGauge } from "./SingleCategoryGauge";
import { SourcesPanel } from "./SourcesPanel";
import { LogEvidencePanel } from "./LogEvidencePanel";
import { SuggestionChips } from "./SuggestionChips";
import { chartSectionsFromApi } from "../../lib/parseAnswerSections";

/**
 * One answered sub-question of a multi-intent turn. Rendered as its own bordered
 * card so the user can clearly tell which answer belongs to which question. Each
 * card charts its OWN segment.answer_sections (never the merged combined counts)
 * and scopes its section ids under a per-segment message id so the radar/gauge
 * click-to-scroll targets don't collide across cards.
 */
export function AnswerSegmentCard({
  segment,
  index,
  messageId,
  onSuggestionClick,
}: {
  segment: AnswerSegment;
  index: number;
  messageId: string;
  onSuggestionClick?: (value: string) => void;
}) {
  const blocked = segment.allowed === false;
  const isLog = !blocked && segment.answer_source === "log_analysis";

  // Chart strictly from THIS segment's authoritative category counts.
  const chartSections = useMemo(
    () => chartSectionsFromApi(segment.answer_sections),
    [segment.answer_sections]
  );
  const singleSection = chartSections.length === 1 ? chartSections[0] : null;

  // Section ids (used by chart click-to-scroll) must be unique per card.
  const scopedId = `${messageId}-s${index}`;

  const accent = blocked ? "red" : "cyan";
  const accentClasses = {
    red: { border: "border-red/25", chip: "bg-red/10 text-red border-red/25", num: "bg-red/12 text-red border-red/25" },
    cyan: { border: "border-cyan/20", chip: "bg-cyan/10 text-cyan border-cyan/25", num: "bg-cyan/10 text-cyan border-cyan/25" },
  }[accent];

  return (
    <motion.div
      // Matches jumpToAnswerSection's fallback target `message-${messageId}` so
      // a chart click still lands on this card when a category has no rendered
      // <answer-section> (scopedId here is the same id the chart/markdown use).
      id={`message-${scopedId}`}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.28, ease: "easeOut", delay: index * 0.05 }}
      className={clsx(
        "rounded-xl border bg-void/40 px-3.5 py-3 sm:px-4",
        accentClasses.border
      )}
    >
      {/* Which sub-question this card answers. */}
      <div className="mb-2.5 flex items-start gap-2.5">
        <span
          className={clsx(
            "mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-md border font-mono text-[11px] font-bold tabular-nums",
            accentClasses.num
          )}
        >
          {index + 1}
        </span>
        <p className="min-w-0 flex-1 pt-0.5 text-[13px] font-medium leading-snug text-text-mid">
          {segment.display_title || segment.query}
        </p>
      </div>

      {blocked && (
        <div className="mb-2 flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider text-red">
          <ShieldWarning size={13} weight="bold" aria-hidden="true" />
          Guardrail blocked{segment.guardrail_category ? ` · ${segment.guardrail_category}` : ""}
        </div>
      )}
      {isLog && (
        <div className="mb-2 flex w-fit items-center gap-1.5 rounded border border-green/30 bg-green/10 px-1.5 py-0.5 font-mono text-[11px] uppercase tracking-wider text-green">
          <Terminal size={12} weight="bold" aria-hidden="true" />
          Log Analysis
        </div>
      )}

      {!blocked && chartSections.length >= 2 && (
        <AnswerVisualization sections={chartSections} messageId={scopedId} />
      )}
      {!blocked && chartSections.length < 2 && singleSection && (
        <SingleCategoryGauge section={singleSection} />
      )}

      <MarkdownMessage
        text={segment.answer}
        messageId={scopedId}
        groundedIds={segment.grounded_ids}
        nodes={segment.nodes}
        presentation={segment.answer_presentation}
      />

      {segment.nodes && segment.nodes.length > 0 && <SourcesPanel nodes={segment.nodes} />}

      {segment.log_evidence && segment.log_evidence.length > 0 && (
        <LogEvidencePanel entries={segment.log_evidence} />
      )}

      {segment.suggestions && segment.suggestions.length > 0 && (
        <SuggestionChips
          suggestions={segment.suggestions}
          actions={segment.suggestion_actions}
          sourceQuery={segment.query}
          onPick={onSuggestionClick}
        />
      )}
    </motion.div>
  );
}
