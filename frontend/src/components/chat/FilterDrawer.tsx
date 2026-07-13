import { AnimatePresence, motion } from "framer-motion";
import { Funnel } from "@phosphor-icons/react";
import { FilterList } from "./FilterList";

interface FilterDrawerProps {
  open: boolean;
  onClose: () => void;
  filters: Record<string, unknown>;
}

export function FilterDrawer({ open, onClose, filters }: FilterDrawerProps) {
  return (
    <AnimatePresence>
      {open && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="absolute inset-0 bg-black/60"
            onClick={onClose}
            aria-hidden="true"
          />
          <motion.div
            initial={{ x: "-100%" }}
            animate={{ x: 0 }}
            exit={{ x: "-100%" }}
            transition={{ duration: 0.25, ease: "easeOut" }}
            className="absolute inset-y-0 left-0 flex w-[280px] max-w-[85vw] flex-col border-r border-border-dim bg-void-raised"
            role="dialog"
            aria-label="Extracted filters"
          >
            <div className="flex items-center justify-between border-b border-border-dim px-4 py-3.5">
              <span className="flex items-center gap-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.2em] text-text-mid">
                <Funnel size={12} weight="bold" className="text-cyan" aria-hidden="true" />
                Extracted Filters
              </span>
              <button
                type="button"
                onClick={onClose}
                aria-label="Close filters panel"
                className="flex h-7 w-7 cursor-pointer items-center justify-center rounded text-text-mid hover:text-cyan"
              >
                <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                  <path d="M18 6 6 18M6 6l12 12" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </button>
            </div>
            <div className="flex-1 overflow-y-auto px-4 py-4">
              <FilterList filters={filters} />
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}
