import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion } from "framer-motion";
import { X, Spinner, WarningCircle } from "@phosphor-icons/react";
import {
  fetchGraphNeighbors,
  type GraphNeighbors,
  type GraphNodeRef,
} from "../../lib/api";
import { ACCENT_HEX, accentForNodeType, hexToRgba, humanizeLabel } from "../../lib/colorTokens";
import { iconForNodeType } from "../../lib/nodeIcons";
import { useReducedMotion } from "../../hooks/useReducedMotion";

/**
 * On-demand explorer for one node's real graph neighbourhood.
 *
 * Everything shown here is fetched live from Neo4j through the standalone
 * /graph router - it is the actual stored relationships, not anything inferred
 * from the answer text. That is the whole point of the panel: the answer says
 * what it found, this shows what the graph holds.
 *
 * Isolation: it only ever runs because the reader clicked, it owns its loading
 * and error states, and a failure renders inline here. Nothing in this
 * component can alter the answer it was opened from.
 */

function NodeChip({ node, index }: { node: GraphNodeRef; index: number }) {
  const accent = accentForNodeType(node.node_type);
  const hex = ACCENT_HEX[accent];
  const Icon = iconForNodeType(node.node_type);
  return (
    <motion.li
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.28, delay: Math.min(index * 0.025, 0.4), ease: "easeOut" }}
      className="flex items-center gap-2 rounded-lg border px-2.5 py-1.5"
      style={{
        borderColor: hexToRgba(hex, 0.28),
        background: `linear-gradient(140deg, ${hexToRgba(hex, 0.12)} 0%, rgba(13,14,23,0.82) 60%)`,
        boxShadow: "inset 0 1px 0 rgba(255,255,255,0.08)",
      }}
    >
      <Icon size={13} weight="bold" color={hex} aria-hidden="true" />
      <span className="min-w-0 flex-1 truncate text-[13px] text-white">{node.name}</span>
      <span className="shrink-0 font-mono text-[10px]" style={{ color: hex }}>
        {node.external_id}
      </span>
    </motion.li>
  );
}

export function NodeGraphExplorer({
  externalId,
  onClose,
}: {
  externalId: string;
  onClose: () => void;
}) {
  const [data, setData] = useState<GraphNeighbors | null>(null);
  const [error, setError] = useState<string | null>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const reducedMotion = useReducedMotion();

  useEffect(() => {
    const controller = new AbortController();
    setData(null);
    setError(null);
    fetchGraphNeighbors(externalId, controller.signal)
      .then(setData)
      .catch((err: unknown) => {
        // An abort is a normal unmount, not a failure worth showing.
        if (err instanceof DOMException && err.name === "AbortError") return;
        setError(err instanceof Error ? err.message : "Could not load the graph.");
      });
    return () => controller.abort();
  }, [externalId]);

  // Escape closes, and focus starts on the close button so the panel is
  // keyboard-operable without trapping the reader inside it.
  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const anchorAccent = data ? accentForNodeType(data.anchor.node_type) : "cyan";
  const anchorHex = ACCENT_HEX[anchorAccent];

  return createPortal(
    <AnimatePresence>
      <motion.div
        key="backdrop"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.2 }}
        className="fixed inset-0 z-[100] flex items-center justify-center bg-void/80 p-4"
        onClick={onClose}
        role="presentation"
      >
        <motion.div
          role="dialog"
          aria-modal="true"
          aria-label={`Graph neighbourhood for ${externalId}`}
          initial={reducedMotion ? { opacity: 0 } : { opacity: 0, y: 14, scale: 0.97 }}
          animate={reducedMotion ? { opacity: 1 } : { opacity: 1, y: 0, scale: 1 }}
          exit={reducedMotion ? { opacity: 0 } : { opacity: 0, y: 10, scale: 0.98 }}
          transition={{ duration: 0.32, ease: [0.16, 1, 0.3, 1] }}
          onClick={(event) => event.stopPropagation()}
          className="relative flex max-h-[82vh] w-full max-w-3xl flex-col overflow-hidden rounded-2xl border border-cyan/25"
          style={{
            background:
              "linear-gradient(150deg, rgba(0,245,255,0.08) 0%, rgba(10,10,18,0.96) 45%, rgba(124,58,237,0.07) 100%), rgba(8,8,14,0.98)",
            boxShadow:
              "inset 0 1px 0 rgba(255,255,255,0.14), 0 40px 90px -40px rgba(0,245,255,0.5)",
          }}
        >
          <header className="flex items-start justify-between gap-3 border-b border-border-dim px-5 py-4">
            <div className="min-w-0">
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-text-dim">
                Graph neighbourhood
              </p>
              <h2 className="mt-1 flex items-center gap-2 font-display text-lg font-semibold text-white">
                <span className="truncate">{data ? data.anchor.name : externalId}</span>
                <span
                  className="shrink-0 rounded border px-1.5 py-0.5 font-mono text-[11px]"
                  style={{
                    color: anchorHex,
                    borderColor: hexToRgba(anchorHex, 0.4),
                    background: hexToRgba(anchorHex, 0.12),
                  }}
                >
                  {data ? data.anchor.external_id : externalId}
                </span>
              </h2>
              {data && (
                <p className="mt-1 font-mono text-[11px] text-text-mid">
                  {humanizeLabel(data.anchor.node_type)} · {data.total} direct{" "}
                  {data.total === 1 ? "relationship" : "relationships"} in the graph
                </p>
              )}
            </div>
            <button
              ref={closeRef}
              type="button"
              onClick={onClose}
              aria-label="Close graph explorer"
              className="shrink-0 rounded-lg border border-border-dim p-1.5 text-text-mid outline-none transition-colors hover:border-cyan/50 hover:text-cyan focus-visible:border-cyan focus-visible:text-cyan"
            >
              <X size={15} weight="bold" />
            </button>
          </header>

          <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
            {!data && !error && (
              <div className="flex items-center justify-center gap-2 py-14 font-mono text-xs text-text-mid">
                <Spinner size={15} className="animate-spin" aria-hidden="true" />
                Querying the knowledge graph…
              </div>
            )}

            {error && (
              <div
                role="alert"
                className="flex items-start gap-2.5 rounded-lg border border-amber/30 bg-amber/10 px-3.5 py-3 text-[13px] text-amber"
              >
                <WarningCircle size={16} weight="bold" className="mt-px shrink-0" aria-hidden="true" />
                <span>{error}</span>
              </div>
            )}

            {data && data.groups.length === 0 && (
              <p className="py-12 text-center font-mono text-xs text-text-mid">
                This node has no outgoing or incoming relationships in the graph.
              </p>
            )}

            <div className="space-y-5">
              {data?.groups.map((group, groupIndex) => {
                const groupAccent = group.nodes[0]
                  ? ACCENT_HEX[accentForNodeType(group.nodes[0].node_type)]
                  : ACCENT_HEX.cyan;
                return (
                  <motion.section
                    key={`${group.relationship}-${group.direction}`}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.3, delay: groupIndex * 0.06, ease: "easeOut" }}
                  >
                    <div className="mb-2 flex items-center gap-2">
                      <span
                        className="h-px flex-1"
                        style={{ background: `linear-gradient(90deg, ${groupAccent}, transparent)` }}
                      />
                      <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-text-mid">
                        {group.label}
                      </span>
                      <span
                        className="rounded-full px-1.5 py-0.5 font-mono text-[10px]"
                        style={{ color: groupAccent, background: hexToRgba(groupAccent, 0.12) }}
                      >
                        {group.nodes.length}
                        {group.truncated ? "+" : ""}
                      </span>
                    </div>
                    <ul className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
                      {group.nodes.map((node, index) => (
                        <NodeChip key={node.external_id} node={node} index={index} />
                      ))}
                    </ul>
                    {group.truncated && (
                      <p className="mt-1.5 font-mono text-[10px] text-text-dim">
                        Showing the first {group.nodes.length} — this node has more.
                      </p>
                    )}
                  </motion.section>
                );
              })}
            </div>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>,
    document.body
  );
}
