import { motion } from "framer-motion";
import { MagnifyingGlass, Check, X } from "@phosphor-icons/react";
import type { Correction } from "../../lib/types";

/**
 * A blocking "Did you mean X?" gate shown when a query returned no info but a
 * spell-corrected version resolves. While it's pending, the chat input is
 * disabled (handled in Chat) so the user must pick Yes or No. Both choices
 * re-run the full guardrail + pipeline, so security is unchanged either way.
 */
export function CorrectionGate({
  correction,
  answered,
  onConfirm,
  onReject,
}: {
  correction: Correction;
  answered: boolean;
  onConfirm: () => void;
  onReject: () => void;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.28, ease: "easeOut" }}
      className="rounded-xl border border-cyan/25 bg-void-panel/70 px-4 py-3"
    >
      <div className="mb-2 flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider text-cyan">
        <MagnifyingGlass size={13} weight="bold" aria-hidden="true" />
        No results — did you mean
      </div>
      <p className="mb-3 text-sm text-[#e6f6f8]">
        “{correction.suggested}”
        <span className="mt-1 block font-mono text-[11px] text-text-dim">
          you searched: {correction.original}
        </span>
      </p>
      <div className="flex gap-2">
        <button
          type="button"
          onClick={onConfirm}
          disabled={answered}
          className="inline-flex items-center gap-1.5 rounded-lg border border-cyan/40 bg-cyan/15 px-3 py-1.5 font-mono text-xs font-semibold text-cyan transition-colors hover:border-cyan/70 hover:bg-cyan/25 disabled:cursor-default disabled:opacity-60"
        >
          <Check size={13} weight="bold" aria-hidden="true" />
          Yes, search this
        </button>
        <button
          type="button"
          onClick={onReject}
          disabled={answered}
          className="inline-flex items-center gap-1.5 rounded-lg border border-border-glow bg-void-raised px-3 py-1.5 font-mono text-xs text-text-mid transition-colors hover:border-red/40 hover:text-red disabled:cursor-default disabled:opacity-60"
        >
          <X size={13} weight="bold" aria-hidden="true" />
          No, keep mine
        </button>
      </div>
    </motion.div>
  );
}
