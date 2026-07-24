import { useMemo } from "react";
import { motion } from "framer-motion";
import { clsx } from "clsx";
import { Robot, ShieldWarning, Terminal, UserCircle } from "@phosphor-icons/react";
import type { ChatMessage } from "../../lib/types";
import { MarkdownMessage } from "./MarkdownMessage";
import { AnswerVisualization } from "./AnswerVisualization";
import { SingleCategoryGauge } from "./SingleCategoryGauge";
import { SourcesPanel } from "./SourcesPanel";
import { LogEvidencePanel } from "./LogEvidencePanel";
import { useTypewriter } from "../../hooks/useTypewriter";
import {
  chartSectionsFromApi,
  parseNodeSectionCounts,
} from "../../lib/parseAnswerSections";

export function MessageBubble({ message, typewrite }: { message: ChatMessage; typewrite: boolean }) {
  const isUser = message.role === "user";
  const { displayed, done } = useTypewriter(message.text, !isUser && typewrite, 3);
  const blocked = message.allowed === false;
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

  const stateColor = blocked ? "red" : message.isMock ? "amber" : "cyan";
  const stateClasses = {
    red: { border: "border-red/30", ring: "bg-red/10 text-red border-red/30", glow: "rgba(255,51,102,0.18)" },
    amber: { border: "border-amber/25", ring: "bg-amber/10 text-amber border-amber/30", glow: "rgba(255,215,0,0.14)" },
    cyan: { border: "border-cyan/25", ring: "bg-cyan/10 text-cyan border-cyan/30", glow: "rgba(0,245,255,0.16)" },
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
          "relative max-w-[92%] overflow-visible rounded-2xl rounded-tl-sm border bg-void-panel/80 px-4 py-3 backdrop-blur-sm sm:max-w-[80%]",
          stateClasses.border
        )}
        style={{ boxShadow: `0 4px 28px -10px ${stateClasses.glow}` }}
      >
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 opacity-60"
          style={{
            background: `radial-gradient(180px circle at 0% 0%, ${stateClasses.glow}, transparent 70%)`,
          }}
        />

        {blocked && (
          <div className="relative mb-2 flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider text-red">
            <ShieldWarning size={14} weight="bold" aria-hidden="true" />
            Guardrail blocked{message.guardrailCategory ? ` · ${message.guardrailCategory}` : ""}
          </div>
        )}
        {!blocked && message.answerSource === "log_analysis" && (
          <div className="relative mb-2 flex w-fit items-center gap-1.5 rounded border border-green/30 bg-green/10 px-1.5 py-0.5 font-mono text-[11px] uppercase tracking-wider text-green">
            <Terminal size={13} weight="bold" aria-hidden="true" />
            Log Analysis
          </div>
        )}
        {!blocked && done && chartSections.length >= 2 && (
          <div className="relative">
            <AnswerVisualization sections={chartSections} messageId={message.id} />
          </div>
        )}

        {!blocked && done && chartSections.length < 2 && singleSection && (
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
          />
          {!done && <span className="ml-0.5 inline-block h-4 w-[7px] translate-y-0.5 bg-cyan motion-safe:animate-blink" />}
        </div>

        {message.isMock && done && (
          <p className="relative mt-2 font-mono text-[10px] uppercase tracking-wider text-amber/80">
            ⚠ mock response · backend offline
          </p>
        )}

        {done && message.nodes && (
          <div className="relative">
            <SourcesPanel nodes={message.nodes} />
          </div>
        )}

        {done && message.logEvidence && message.logEvidence.length > 0 && (
          <div className="relative">
            <LogEvidencePanel entries={message.logEvidence} />
          </div>
        )}

        {done && typeof message.latencyMs === "number" && (
          <p className="relative mt-2 font-mono text-[10px] text-text-dim">{message.latencyMs}ms</p>
        )}
      </div>
    </motion.div>
  );
}
