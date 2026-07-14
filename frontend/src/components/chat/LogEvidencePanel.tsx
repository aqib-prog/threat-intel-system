import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { clsx } from "clsx";
import { MagnifyingGlass } from "@phosphor-icons/react";
import type { LogEvidenceEntry } from "../../lib/types";
import { ACCENT_CLASSES, ACCENT_HEX, hexToRgba } from "../../lib/colorTokens";

const CONFIDENCE_LABEL: Record<LogEvidenceEntry["confidence"], string> = {
  high: "High Confidence",
  medium: "Medium Confidence",
  low: "Low Confidence",
};

const CONFIDENCE_DOT: Record<LogEvidenceEntry["confidence"], string> = {
  high: "bg-green",
  medium: "bg-amber",
  low: "bg-text-dim",
};

const CONFIDENCE_BAR: Record<LogEvidenceEntry["confidence"], string> = {
  high: "bg-green",
  medium: "bg-amber",
  low: "bg-text-dim",
};

/** Always-visible at-a-glance breakdown of how many matched techniques are
 * high/medium/low confidence - lets a user judge overall signal quality of
 * a log-analysis response without opening the per-technique detail below. */
function ConfidenceBreakdown({ entries }: { entries: LogEvidenceEntry[] }) {
  const counts = { high: 0, medium: 0, low: 0 };
  for (const entry of entries) counts[entry.confidence] += 1;
  const total = entries.length;

  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-border-dim">
        {(["high", "medium", "low"] as const).map((level) =>
          counts[level] > 0 ? (
            <motion.div
              key={level}
              className={clsx("h-full", CONFIDENCE_BAR[level])}
              initial={{ width: 0 }}
              animate={{ width: `${(counts[level] / total) * 100}%` }}
              transition={{ duration: 0.5, ease: "easeOut" }}
            />
          ) : null
        )}
      </div>
      <div className="flex flex-wrap items-center gap-3 font-mono text-[10px] uppercase tracking-wider text-text-mid">
        {(["high", "medium", "low"] as const).map((level) =>
          counts[level] > 0 ? (
            <span key={level} className="flex items-center gap-1">
              <span className={clsx("h-1.5 w-1.5 rounded-full", CONFIDENCE_BAR[level])} />
              {counts[level]} {level}
            </span>
          ) : null
        )}
      </div>
    </div>
  );
}

/** Shows the exact line(s) from the user's own pasted log that triggered
 * each deterministic technique match - distinct from the prose "Strongest
 * Evidence" markdown section, which describes the match but doesn't quote
 * the raw source line. See backend/log_analysis/analyzer.py. */
export function LogEvidencePanel({ entries }: { entries: LogEvidenceEntry[] }) {
  const [open, setOpen] = useState(false);
  const accent = ACCENT_CLASSES.amber;
  const glow = hexToRgba(ACCENT_HEX.amber, 0.16);

  if (entries.length === 0) return null;

  return (
    <div className="mt-3 flex flex-col gap-2">
      <ConfidenceBreakdown entries={entries} />
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex cursor-pointer items-center gap-1.5 font-mono text-xs text-text-mid transition-colors hover:text-amber"
      >
        <svg
          className={`h-3 w-3 transition-transform duration-200 ${open ? "rotate-90" : ""}`}
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.5"
          aria-hidden="true"
        >
          <path d="M9 6l6 6-6 6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <MagnifyingGlass size={13} weight="bold" aria-hidden="true" />
        Matched Log Lines ({entries.length})
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: "easeInOut" }}
            className="overflow-hidden"
          >
            <div className="mt-2.5 flex flex-col gap-2">
              {entries.map((entry, i) => (
                <motion.div
                  key={`${entry.technique_id}-${i}`}
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.25, delay: i * 0.04, ease: "easeOut" }}
                  className={clsx(
                    "relative overflow-hidden rounded-lg border bg-void-panel/80 p-3 backdrop-blur-sm",
                    accent.border
                  )}
                >
                  <div
                    aria-hidden="true"
                    className="pointer-events-none absolute inset-0 opacity-60"
                    style={{ background: `radial-gradient(140px circle at 0% 0%, ${glow}, transparent 72%)` }}
                  />
                  <div className="relative flex flex-wrap items-center justify-between gap-2">
                    <div className="flex min-w-0 items-center gap-2">
                      <span className="truncate font-display text-sm font-medium text-white">
                        {entry.technique_name}
                      </span>
                      <span
                        className={clsx(
                          "shrink-0 rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold",
                          accent.border,
                          accent.text,
                          accent.bg
                        )}
                      >
                        {entry.technique_id}
                      </span>
                    </div>
                    <span className="flex shrink-0 items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-text-mid">
                      <span className={clsx("h-1.5 w-1.5 rounded-full", CONFIDENCE_DOT[entry.confidence])} />
                      {CONFIDENCE_LABEL[entry.confidence]}
                    </span>
                  </div>
                  <pre className="relative mt-2 overflow-x-auto rounded-md border border-border-dim bg-void px-2.5 py-2 font-mono text-[11px] leading-relaxed text-text-mid">
                    <code>{entry.matched_line}</code>
                  </pre>
                </motion.div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
