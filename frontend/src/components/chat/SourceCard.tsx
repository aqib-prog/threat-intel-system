import { motion } from "framer-motion";
import { clsx } from "clsx";
import { MAX_RELEVANCE_SCORE, type NodeSource } from "../../lib/types";
import { ACCENT_CLASSES, ACCENT_HEX, accentForNodeType, hexToRgba, humanizeLabel } from "../../lib/colorTokens";
import { iconForNodeType } from "../../lib/nodeIcons";

export function SourceCard({ node, index = 0 }: { node: NodeSource; index?: number }) {
  const accentColor = accentForNodeType(node.node_type);
  const accent = ACCENT_CLASSES[accentColor];
  const glow = hexToRgba(ACCENT_HEX[accentColor], 0.16);
  const Icon = iconForNodeType(node.node_type);
  const score = node.relevance_score ?? 0;
  // Backend clips relevance_score to [0, 10] (retrieval/reranker.py
  // clipped_score) - not already a 0-1 fraction.
  const scorePct = Math.round(Math.min(1, Math.max(0, score / MAX_RELEVANCE_SCORE)) * 100);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: index * 0.04, ease: "easeOut" }}
      whileHover={{ y: -2 }}
      className={clsx(
        "group relative flex flex-col gap-2.5 overflow-hidden rounded-lg border bg-void-panel/80 p-3 backdrop-blur-sm transition-shadow duration-300",
        accent.border
      )}
    >
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-300 group-hover:opacity-100"
        style={{ background: `radial-gradient(140px circle at 18% 0%, ${glow}, transparent 72%)` }}
      />

      <div className="relative flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span
            className={clsx(
              "flex h-7 w-7 shrink-0 items-center justify-center rounded-md border",
              accent.border,
              accent.bg
            )}
          >
            <Icon className={accent.text} size={14} weight="bold" aria-hidden="true" />
          </span>
          <span className="truncate font-display text-sm font-medium text-white">{node.name}</span>
        </div>
        {node.external_id && (
          <span
            className={clsx(
              "shrink-0 rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold",
              accent.border,
              accent.text,
              accent.bg
            )}
          >
            {node.external_id}
          </span>
        )}
      </div>

      <span
        className={clsx(
          "relative w-fit rounded-full px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider",
          accent.bg,
          accent.text
        )}
      >
        {humanizeLabel(node.node_type)}
      </span>

      {node.relevance_score !== null && (
        <div className="relative flex items-center gap-2">
          <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-border-dim">
            <motion.div
              className={clsx("h-full rounded-full", accent.bar)}
              initial={{ width: 0 }}
              animate={{ width: `${scorePct}%` }}
              transition={{ duration: 0.7, delay: 0.1 + index * 0.04, ease: "easeOut" }}
            />
          </div>
          <span className="font-mono text-[10px] text-text-mid">{scorePct}%</span>
        </div>
      )}
    </motion.div>
  );
}
