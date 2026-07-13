import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { clsx } from "clsx";
import { Funnel } from "@phosphor-icons/react";
import { FilterList } from "./FilterList";

export function FilterSidebar({ filters }: { filters: Record<string, unknown> }) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <aside
      className={clsx(
        "hidden shrink-0 flex-col border-r border-border-dim bg-void-raised/60 backdrop-blur-sm transition-[width] duration-200 lg:flex",
        collapsed ? "w-[52px]" : "w-[280px]"
      )}
    >
      <div className="flex items-center justify-between border-b border-border-dim px-4 py-3.5">
        {!collapsed && (
          <span className="flex items-center gap-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.2em] text-text-mid">
            <Funnel size={12} weight="bold" className="text-cyan" aria-hidden="true" />
            Extracted Filters
          </span>
        )}
        <button
          type="button"
          onClick={() => setCollapsed((v) => !v)}
          aria-label={collapsed ? "Expand filters panel" : "Collapse filters panel"}
          className="ml-auto flex h-6 w-6 cursor-pointer items-center justify-center rounded text-text-mid transition-colors hover:text-cyan"
        >
          <svg
            className={`h-4 w-4 transition-transform duration-200 ${collapsed ? "rotate-180" : ""}`}
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            aria-hidden="true"
          >
            <path d="M15 6l-6 6 6 6" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </button>
      </div>

      <AnimatePresence initial={false}>
        {!collapsed && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="flex-1 overflow-y-auto px-4 py-4"
          >
            <FilterList filters={filters} />
          </motion.div>
        )}
      </AnimatePresence>
    </aside>
  );
}
