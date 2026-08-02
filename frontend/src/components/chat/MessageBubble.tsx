import { useMemo } from "react";
import { motion } from "framer-motion";
import { clsx } from "clsx";
import { Robot, ShieldWarning, Terminal, UserCircle, WarningOctagon } from "@phosphor-icons/react";
import type { ChatMessage } from "../../lib/types";
import { MarkdownMessage } from "./MarkdownMessage";
import { AnswerVisualization } from "./AnswerVisualization";
import { SingleCategoryGauge } from "./SingleCategoryGauge";
import { SourcesPanel } from "./SourcesPanel";
import { LogEvidencePanel } from "./LogEvidencePanel";
import { AnswerSegmentCard } from "./AnswerSegmentCard";
import { SuggestionChips } from "./SuggestionChips";
import { useTypewriter } from "../../hooks/useTypewriter";
import {
  chartSectionsFromApi,
  parseNodeSectionCounts,
} from "../../lib/parseAnswerSections";

export function MessageBubble({
  message,
  typewrite,
  onSuggestionClick,
}: {
  message: ChatMessage;
  typewrite: boolean;
  onSuggestionClick?: (value: string) => void;
}) {
  const isUser = message.role === "user";
  // A multi-intent turn (>=2 answered sub-questions) renders one card per
  // segment instead of a single combined answer, so skip the typewriter for it.
  const segments = message.segments && message.segments.length >= 2 ? message.segments : null;
  const { displayed, done } = useTypewriter(message.text, !isUser && typewrite && !segments, 3);
  const requestFailed = Boolean(message.requestError);
  const blocked = message.allowed === false && !requestFailed;
  // Chart from the backend's authoritative category counts. Fall back to node
  // type counts only when the backend didn't supply sections (e.g. mock replies
  // or the log-analysis path) - never by re-parsing the answer prose.
  const apiSections = useMemo(() => chartSectionsFromApi(message.sections), [message.sections]);
  const nodeSections = useMemo(() => parseNodeSectionCounts(message.nodes), [message.nodes]);
  const chartSections = apiSections.length > 0 ? apiSections : nodeSections;
  const singleSection = chartSections.length === 1 ? chartSections[0] : null;

  if (isUser) {
    return (
      <motion.div
        initial={{ opacity: 0, x: 12 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.3, ease: "easeOut" }}
        className="flex items-start justify-end gap-2.5"
      >
        <div className="max-w-[85%] rounded-2xl rounded-tr-sm border border-purple/25 bg-gradient-to-br from-[#151233]/90 to-[#0e1630]/90 px-4 py-3 shadow-[0_4px_24px_-8px_rgba(124,58,237,0.25)] sm:max-w-[70%]">
          <p className="whitespace-pre-wrap text-sm text-[#e4dbff]">{message.text}</p>
        </div>
        <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-purple/30 bg-purple/10 text-purple">
          <UserCircle size={16} weight="bold" aria-hidden="true" />
        </span>
      </motion.div>
    );
  }

  const stateColor = blocked ? "red" : requestFailed ? "amber" : "cyan";
  const stateClasses = {
    red: { border: "border-red/30", ring: "bg-red/10 text-red border-red/30", glow: "rgba(255,51,102,0.18)", spine: "rgba(255,51,102,0.85)", spineSoft: "rgba(255,51,102,0.22)" },
    amber: { border: "border-amber/25", ring: "bg-amber/10 text-amber border-amber/30", glow: "rgba(255,215,0,0.14)", spine: "rgba(255,215,0,0.8)", spineSoft: "rgba(255,215,0,0.2)" },
    cyan: { border: "border-cyan/25", ring: "bg-cyan/10 text-cyan border-cyan/30", glow: "rgba(0,245,255,0.16)", spine: "rgba(0,245,255,0.85)", spineSoft: "rgba(0,245,255,0.22)" },
  }[stateColor];

  return (
    <motion.div
      initial={{ opacity: 0, x: -12 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.3, ease: "easeOut" }}
      className="flex items-start justify-start gap-2.5"
    >
      <span
        className={clsx(
          "mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full border",
          stateClasses.ring
        )}
      >
        <Robot size={16} weight="bold" aria-hidden="true" />
      </span>

      <div
        id={`message-${message.id}`}
        className={clsx(
          "relative max-w-[92%] overflow-visible rounded-2xl rounded-tl-sm border px-4 py-3 sm:max-w-[80%]",
          stateClasses.border
        )}
        style={{
          // Glass sheet lit from the top-left. backdrop-blur was removed on
          // purpose: these bubbles scroll, and a blurred backdrop re-rasterizes
          // on every scroll frame. The layered gradient reproduces the depth.
          background:
            "linear-gradient(145deg, rgba(255,255,255,0.055) 0%, rgba(13,14,23,0.86) 42%, rgba(13,14,23,0.94) 100%)",
          boxShadow: `inset 0 1px 0 rgba(255,255,255,0.13), 0 10px 34px -16px ${stateClasses.glow}`,
        }}
      >
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 opacity-60"
          style={{
            background: `radial-gradient(180px circle at 0% 0%, ${stateClasses.glow}, transparent 70%)`,
          }}
        />

        {/* Left spine: a lit rail marking the full extent of the answer. It
            caps bright at the top, holds a steady low tone down the body, and
            eases off only at the very end - a one-directional fade read as an
            unfinished border on long answers. */}
        <span
          aria-hidden="true"
          className="pointer-events-none absolute inset-y-3 left-0 w-px rounded-full"
          style={{
            background: `linear-gradient(180deg, ${stateClasses.spine} 0%, ${stateClasses.spineSoft} 6%, ${stateClasses.spineSoft} 88%, transparent 100%)`,
          }}
        />

        {segments ? (
          <div className="relative flex flex-col gap-3">
            <div className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.2em] text-text-dim">
              <span className="flex h-4 w-4 items-center justify-center rounded border border-cyan/25 bg-cyan/10 text-[9px] font-bold text-cyan tabular-nums">
                {segments.length}
              </span>
              responses
            </div>
            {segments.map((segment, index) => (
              <AnswerSegmentCard
                key={`${message.id}-s${index}`}
                segment={segment}
                index={index}
                messageId={message.id}
                onSuggestionClick={onSuggestionClick}
              />
            ))}
          </div>
        ) : (
          <>
            {requestFailed && (
              <div
                role="alert"
                className="relative mb-2 flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider text-amber"
              >
                <WarningOctagon size={14} weight="bold" aria-hidden="true" />
                {message.requestError?.title}
              </div>
            )}
            {blocked && (
              <div className="relative mb-2 flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider text-red">
                <ShieldWarning size={14} weight="bold" aria-hidden="true" />
                Guardrail blocked{message.guardrailCategory ? ` · ${message.guardrailCategory}` : ""}
              </div>
            )}
            {!blocked && !requestFailed && message.answerSource === "log_analysis" && (
              <div className="relative mb-2 flex w-fit items-center gap-1.5 rounded border border-green/30 bg-green/10 px-1.5 py-0.5 font-mono text-[11px] uppercase tracking-wider text-green">
                <Terminal size={13} weight="bold" aria-hidden="true" />
                Log Analysis
              </div>
            )}
            {!blocked && !requestFailed && done && chartSections.length >= 2 && (
              <div className="relative">
                <AnswerVisualization sections={chartSections} messageId={message.id} />
              </div>
            )}

            {!blocked && !requestFailed && done && chartSections.length < 2 && singleSection && (
              <div className="relative">
                <SingleCategoryGauge section={singleSection} />
              </div>
            )}

            <div className="relative">
              <MarkdownMessage
                text={displayed}
                messageId={message.id}
                groundedIds={message.groundedIds}
                nodes={message.nodes}
                presentation={done ? message.presentation : undefined}
              />
              {!done && <span className="ml-0.5 inline-block h-4 w-[7px] translate-y-0.5 bg-cyan motion-safe:animate-blink" />}
            </div>

            {!requestFailed && done && message.nodes && (
              <div className="relative">
                <SourcesPanel nodes={message.nodes} />
              </div>
            )}

            {!requestFailed && done && message.logEvidence && message.logEvidence.length > 0 && (
              <div className="relative">
                <LogEvidencePanel entries={message.logEvidence} />
              </div>
            )}

            {!requestFailed && done && message.suggestions && message.suggestions.length > 0 && (
              <SuggestionChips
                suggestions={message.suggestions}
                actions={message.suggestionActions}
                sourceQuery={message.sourceQuery}
                onPick={onSuggestionClick}
              />
            )}
          </>
        )}

        {typeof message.latencyMs === "number" && (done || segments) && (
          <p className="relative mt-2 font-mono text-[10px] text-text-dim">{message.latencyMs}ms</p>
        )}
      </div>
    </motion.div>
  );
}
