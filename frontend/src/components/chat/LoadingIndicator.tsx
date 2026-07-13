import { motion } from "framer-motion";
import { Robot } from "@phosphor-icons/react";
import { useReducedMotion } from "../../hooks/useReducedMotion";

const NODES = [
  { x: 8, y: 18 },
  { x: 24, y: 6 },
  { x: 24, y: 30 },
];

export function LoadingIndicator() {
  const reducedMotion = useReducedMotion();

  return (
    <div className="flex items-start justify-start gap-2.5">
      <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-cyan/30 bg-cyan/10 text-cyan">
        <Robot size={16} weight="bold" aria-hidden="true" />
      </span>

      <div className="relative flex items-center gap-3 overflow-hidden rounded-2xl rounded-tl-sm border border-cyan/25 bg-void-panel/80 px-4 py-3 backdrop-blur-sm">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 opacity-60"
          style={{ background: "radial-gradient(180px circle at 0% 0%, rgba(0,245,255,0.16), transparent 70%)" }}
        />

        <svg viewBox="0 0 32 36" className="relative h-8 w-7 shrink-0" aria-hidden="true">
          {NODES.map((a, i) =>
            NODES.slice(i + 1).map((b, j) => (
              <line
                key={`${i}-${j}`}
                x1={a.x}
                y1={a.y}
                x2={b.x}
                y2={b.y}
                stroke="#00f5ff"
                strokeWidth={1}
                strokeOpacity={0.35}
              />
            ))
          )}
          {NODES.map((n, i) => (
            <motion.circle
              key={i}
              cx={n.x}
              cy={n.y}
              r={2.4}
              fill="#00f5ff"
              animate={reducedMotion ? undefined : { opacity: [0.3, 1, 0.3], r: [2, 3, 2] }}
              transition={{ duration: 1.4, repeat: Infinity, delay: i * 0.25, ease: "easeInOut" }}
            />
          ))}
        </svg>

        <span className="relative font-mono text-xs tracking-wider text-cyan">
          SCANNING KNOWLEDGE GRAPH
        </span>
        <span className="relative flex gap-1">
          {[0, 1, 2].map((i) => (
            <motion.span
              key={i}
              className="h-1.5 w-1.5 rounded-full bg-cyan"
              animate={{ opacity: [0.25, 1, 0.25] }}
              transition={{ duration: 1.1, repeat: Infinity, delay: i * 0.18, ease: "easeInOut" }}
            />
          ))}
        </span>
      </div>
    </div>
  );
}
