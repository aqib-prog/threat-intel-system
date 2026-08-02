import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { clsx } from "clsx";
import { SquaresFour, ShareNetwork } from "@phosphor-icons/react";
import type { NodeSource } from "../../lib/types";
import { SourceCard } from "./SourceCard";
import { SourceGraph } from "./SourceGraph";

type ViewMode = "cards" | "graph";

export function SourcesPanel({ nodes }: { nodes: NodeSource[] }) {
  const [open, setOpen] = useState(false);
  const [view, setView] = useState<ViewMode>("cards");

  if (nodes.length === 0) return null;

  return (
    <div className="mt-3">
      <div className="flex items-center justify-between gap-2">
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          className="flex cursor-pointer items-center gap-1.5 font-mono text-xs text-text-mid transition-colors hover:text-cyan"
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
          View Sources ({nodes.length})
        </button>

        {open && (
          <div
            className="flex items-center gap-1 rounded-lg border border-cyan/15 p-1"
            style={{
              // Matches the source cards and answer charts - one material for
              // the whole panel rather than a flat control beside glass cards.
              background:
                "linear-gradient(145deg, rgba(0,245,255,0.07) 0%, rgba(13,14,23,0.82) 55%, rgba(13,14,23,0.92) 100%)",
              boxShadow: "inset 0 1px 0 rgba(255,255,255,0.10)",
            }}
          >
            <button
              type="button"
              onClick={() => setView("cards")}
              aria-pressed={view === "cards"}
              aria-label="Card view"
              className={clsx(
                "flex cursor-pointer items-center gap-1 rounded-md px-2 py-1 font-mono text-[10px] uppercase tracking-wider transition-colors",
                view === "cards" ? "bg-cyan/15 text-cyan" : "text-text-dim hover:text-text-mid"
              )}
            >
              <SquaresFour size={13} weight="bold" />
              Cards
            </button>
            <button
              type="button"
              onClick={() => setView("graph")}
              aria-pressed={view === "graph"}
              aria-label="Graph view"
              className={clsx(
                "flex cursor-pointer items-center gap-1 rounded-md px-2 py-1 font-mono text-[10px] uppercase tracking-wider transition-colors",
                view === "graph" ? "bg-cyan/15 text-cyan" : "text-text-dim hover:text-text-mid"
              )}
            >
              <ShareNetwork size={13} weight="bold" />
              Graph
            </button>
          </div>
        )}
      </div>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: "easeInOut" }}
            className="overflow-hidden"
          >
            <div className="mt-2.5">
              {view === "cards" ? (
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  {nodes.map((node, i) => (
                    <SourceCard key={`${node.external_id ?? node.name}-${i}`} node={node} index={i} />
                  ))}
                </div>
              ) : (
                <SourceGraph nodes={nodes} />
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
