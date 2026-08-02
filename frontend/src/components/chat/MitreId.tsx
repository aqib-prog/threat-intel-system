import { lazy, Suspense, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion } from "framer-motion";
import { ArrowSquareOut, ShareNetwork } from "@phosphor-icons/react";
import { describeMitreId, mitreUrl } from "../../lib/mitre";

// Loaded only when a reader actually opens the explorer, so the graph panel and
// its animation code never enter the initial chat bundle.
const NodeGraphExplorer = lazy(() =>
  import("./NodeGraphExplorer").then((m) => ({ default: m.NodeGraphExplorer }))
);

// Only identifiers the graph endpoint can resolve get an explore action;
// anything else keeps exactly the previous rendering.
const EXPLORABLE_ID_RE = /^(?:TA|DET|DC|DS|AN|T|G|S|M|C)\d{4}(?:\.\d{3})?$/i;

export function MitreId({
  id,
  authoritativeUrl,
}: {
  id: string;
  authoritativeUrl?: string | null;
}) {
  const [open, setOpen] = useState(false);
  const [explorerOpen, setExplorerOpen] = useState(false);
  const chipRef = useRef<HTMLSpanElement>(null);
  // Viewport coordinates for the portalled tooltip, plus which side of the chip
  // it sits on when there isn't room above.
  const [placement, setPlacement] = useState<{ x: number; y: number; below: boolean } | null>(null);
  const url = authoritativeUrl || mitreUrl(id);
  const explorable = EXPLORABLE_ID_RE.test(id.trim());

  // The tooltip is rendered into document.body rather than beside the chip.
  // Answer-section panels use `overflow: hidden`, which clipped a tooltip that
  // extended past the panel edge - the top of it was simply cut off. A portal
  // escapes every ancestor's overflow and stacking context; position: fixed
  // then keeps it locked to the chip's on-screen position.
  const reposition = useCallback(() => {
    const chip = chipRef.current;
    if (!chip) return;
    const rect = chip.getBoundingClientRect();
    // Flip below when the panel would run off the top of the viewport.
    const below = rect.top < 132;
    setPlacement({
      x: rect.left + rect.width / 2,
      y: below ? rect.bottom + 8 : rect.top - 8,
      below,
    });
  }, []);

  useLayoutEffect(() => {
    if (!open) return;
    reposition();
  }, [open, reposition]);

  useEffect(() => {
    if (!open) return;
    // `capture` so the chat's own scroll container is heard, not just window.
    const onScrollOrResize = () => reposition();
    window.addEventListener("scroll", onScrollOrResize, true);
    window.addEventListener("resize", onScrollOrResize);
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as Node;
      if (chipRef.current?.contains(target)) return;
      // Clicking inside the tooltip must not dismiss it before the action runs.
      if ((target as HTMLElement)?.closest?.(`[data-mitre-tip="${id}"]`)) return;
      setOpen(false);
    };
    window.addEventListener("pointerdown", onPointerDown);
    return () => {
      window.removeEventListener("scroll", onScrollOrResize, true);
      window.removeEventListener("resize", onScrollOrResize);
      window.removeEventListener("pointerdown", onPointerDown);
    };
  }, [open, reposition, id]);

  const chipClass =
    "rounded border border-amber/30 bg-amber/10 px-1 py-px font-mono font-semibold text-amber no-underline";

  // Hover is tracked on the WRAPPER, not the chip. An inline icon beside the id
  // sat inside the answer's own parentheses - "( T1047 [icon] )" - which read as
  // clutter and gave no clue what it did. The action now lives in the tooltip
  // that already existed, so the sentence stays clean and the affordance
  // arrives labelled. Tracking hover on the wrapper is what lets the pointer
  // travel from the chip into the tooltip without it closing.
  const hoverHandlers = {
    onMouseEnter: () => setOpen(true),
    onMouseLeave: () => setOpen(false),
    onFocus: () => setOpen(true),
    onBlur: (event: React.FocusEvent<HTMLSpanElement>) => {
      if (!event.currentTarget.contains(event.relatedTarget as Node | null)) {
        setOpen(false);
      }
    },
  };

  return (
    <span className="relative inline-block" {...hoverHandlers}>
      {/* The chip OPENS the actions rather than being one itself. Previously it
          was a bare link: clicking navigated away with no indication that was
          going to happen, and there was nowhere to offer the graph. It stays
          focusable and toggles on click so the tooltip is reachable by keyboard
          and on touch, where there is no hover. */}
      <span
        ref={chipRef}
        role="button"
        tabIndex={0}
        aria-haspopup="true"
        aria-expanded={open}
        aria-describedby={`mitre-tip-${id}`}
        onClick={() => setOpen((value) => !value)}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            setOpen((value) => !value);
          }
        }}
        className={`${chipClass} cursor-pointer outline-none transition-colors hover:border-amber/60 hover:bg-amber/20 focus-visible:border-amber focus-visible:bg-amber/20`}
      >
        {id}
      </span>

      {createPortal(
        <AnimatePresence>
          {open && placement && (
            <motion.span
              id={`mitre-tip-${id}`}
              role="tooltip"
              data-mitre-tip={id}
              initial={{ opacity: 0, y: placement.below ? -4 : 4, scale: 0.97 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: placement.below ? -2 : 2, scale: 0.98 }}
              transition={{ duration: 0.16, ease: [0.16, 1, 0.3, 1] }}
              onMouseEnter={() => setOpen(true)}
              onMouseLeave={() => setOpen(false)}
              style={{
                position: "fixed",
                left: placement.x,
                top: placement.y,
                // Clamped horizontally so a chip near either edge still shows a
                // fully visible panel instead of one hanging off-screen.
                transform: `translate(-50%, ${placement.below ? "0" : "-100%"})`,
                maxWidth: "min(20rem, calc(100vw - 16px))",
              }}
              className="z-[90] block"
            >
            <span className="block min-w-[15rem] whitespace-nowrap rounded-md border border-border-glow bg-void-raised p-1.5 font-mono text-[11px] text-white shadow-[0_10px_30px_-12px_rgba(0,245,255,0.7)]">
              {/* Identity line. Describes WHAT the id is; the rows below are the
                  things you can do with it. */}
              <span className="block px-1 pb-1 pt-0.5 text-text-mid">{describeMitreId(id)}</span>

              {/* Row 1 - the authoritative MITRE page. This used to be a click
                  on the chip itself, which gave no hint it was a link and no
                  room for a label. Promoting it into the tooltip makes both
                  actions equal, labelled, and reachable by keyboard. */}
              {url ? (
                <motion.a
                  href={url}
                  target="_blank"
                  rel="noreferrer"
                  initial={{ opacity: 0, x: -4 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.2, delay: 0.04, ease: "easeOut" }}
                  onClick={() => setOpen(false)}
                  className="group/act flex w-full items-center gap-1.5 rounded px-1 py-1 text-left text-amber no-underline outline-none transition-colors hover:bg-amber/12 focus-visible:bg-amber/12"
                >
                  <motion.span
                    aria-hidden="true"
                    className="flex"
                    // Lifts away from the row, the direction it sends you.
                    whileHover={{ x: 1, y: -1 }}
                    transition={{ type: "spring", stiffness: 420, damping: 18 }}
                  >
                    <ArrowSquareOut size={12} weight="bold" />
                  </motion.span>
                  <span className="underline-offset-2 group-hover/act:underline">
                    View on attack.mitre.org
                  </span>
                  <span className="ml-auto pl-3 text-text-dim transition-transform duration-200 group-hover/act:-translate-y-px group-hover/act:translate-x-px">
                    ↗
                  </span>
                </motion.a>
              ) : (
                <span className="block px-1 py-1 text-text-dim">No public page</span>
              )}

              {/* Row 2 - the live graph neighbourhood. */}
              {explorable && (
                <motion.button
                  type="button"
                  initial={{ opacity: 0, x: -4 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.2, delay: 0.1, ease: "easeOut" }}
                  onClick={() => {
                    setExplorerOpen(true);
                    setOpen(false);
                  }}
                  className="group/act flex w-full items-center gap-1.5 rounded px-1 py-1 text-left text-cyan outline-none transition-colors hover:bg-cyan/12 focus-visible:bg-cyan/12"
                >
                  <motion.span
                    aria-hidden="true"
                    className="flex"
                    // Slow idle pulse so the action reads as live data.
                    animate={{ scale: [1, 1.16, 1] }}
                    transition={{ duration: 2.2, repeat: Infinity, ease: "easeInOut" }}
                  >
                    <ShareNetwork size={12} weight="bold" />
                  </motion.span>
                  <span className="underline-offset-2 group-hover/act:underline">
                    Explore relationships
                  </span>
                  <span className="ml-auto pl-3 text-text-dim transition-transform duration-200 group-hover/act:translate-x-0.5">
                    →
                  </span>
                </motion.button>
              )}
              <span
                className={
                  placement.below
                    ? "absolute bottom-full left-1/2 -translate-x-1/2 border-4 border-transparent border-b-border-glow"
                    : "absolute left-1/2 top-full -translate-x-1/2 border-4 border-transparent border-t-border-glow"
                }
              />
            </span>
          </motion.span>
        )}
        </AnimatePresence>,
        document.body
      )}

      {explorerOpen && (
        <Suspense fallback={null}>
          <NodeGraphExplorer
            externalId={id.trim().toUpperCase()}
            onClose={() => setExplorerOpen(false)}
          />
        </Suspense>
      )}
    </span>
  );
}
