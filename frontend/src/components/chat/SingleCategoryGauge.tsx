import { clsx } from "clsx";
import { motion } from "framer-motion";
import { Gauge } from "@phosphor-icons/react";
import { ACCENT_CLASSES, ACCENT_HEX } from "../../lib/colorTokens";
import { categoryMetaFor } from "../../lib/answerSections";
import type { AnswerSectionCount } from "../../lib/parseAnswerSections";

const GAUGE_SIZE = 84;
const GAUGE_CENTER = GAUGE_SIZE / 2;
const GAUGE_RADIUS = 34;
const CIRCUMFERENCE = 2 * Math.PI * GAUGE_RADIUS;
const ARC_FRACTION = 0.75; // ~270deg sweep, leaving a HUD-style gap at the bottom

export function SingleCategoryGauge({ section }: { section: AnswerSectionCount }) {
  const accent = ACCENT_CLASSES[section.accent];
  const hex = ACCENT_HEX[section.accent];
  const Icon = section.icon;
  const meta = categoryMetaFor(section.label);
  const dash = CIRCUMFERENCE * ARC_FRACTION;

  return (
    <div
      className="relative mb-3 overflow-hidden rounded-xl border border-cyan/20 p-4"
      style={{
        background:
          "linear-gradient(140deg, rgba(0,245,255,0.09) 0%, rgba(180,220,255,0.03) 45%, rgba(124,58,237,0.07) 100%), rgba(10,10,18,0.72)",
        boxShadow:
          "inset 0 1px 0 rgba(255,255,255,0.16), inset 0 0 40px -22px rgba(0,245,255,0.55), 0 18px 44px -30px rgba(0,245,255,0.4)",
      }}
    >
      <div className="mb-3 flex items-start gap-2">
        <Gauge size={14} weight="bold" className="mt-0.5 shrink-0 text-cyan" aria-hidden="true" />
        <div>
          <p className="font-mono text-[11px] font-semibold uppercase tracking-wider text-cyan">
            Category Snapshot
          </p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="relative shrink-0" style={{ width: GAUGE_SIZE, height: GAUGE_SIZE }}>
          <svg viewBox={`0 0 ${GAUGE_SIZE} ${GAUGE_SIZE}`} width={GAUGE_SIZE} height={GAUGE_SIZE} className="-rotate-90">
            <circle
              cx={GAUGE_CENTER}
              cy={GAUGE_CENTER}
              r={GAUGE_RADIUS}
              fill="none"
              stroke="rgba(255,255,255,0.08)"
              strokeWidth={5}
              strokeDasharray={`${dash} ${CIRCUMFERENCE}`}
              strokeLinecap="round"
            />
            {/* The arc draws itself on mount instead of appearing complete -
                the reading lands as a measurement being taken. */}
            <motion.circle
              cx={GAUGE_CENTER}
              cy={GAUGE_CENTER}
              r={GAUGE_RADIUS}
              fill="none"
              stroke={hex}
              strokeWidth={5}
              strokeLinecap="round"
              strokeDasharray={`${dash} ${CIRCUMFERENCE}`}
              initial={{ strokeDashoffset: dash }}
              animate={{ strokeDashoffset: 0 }}
              transition={{ duration: 1.05, ease: [0.16, 1, 0.3, 1] }}
              style={{ filter: `drop-shadow(0 0 6px ${hex})` }}
            />
          </svg>
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
            <span className="font-mono text-xl font-semibold text-white">{section.count}</span>
          </div>
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <Icon size={13} weight="bold" className={accent.text} aria-hidden="true" />
            <span className={clsx("font-mono text-sm font-semibold uppercase tracking-wider", accent.text)}>
              {section.label}
            </span>
          </div>
          {meta && <p className="mt-1 text-[11px] leading-snug text-text-mid">{meta.description}</p>}
        </div>
      </div>
    </div>
  );
}
