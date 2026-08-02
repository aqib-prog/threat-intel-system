import { useMemo, useRef, useState } from "react";
import { motion } from "framer-motion";
import { clsx } from "clsx";
import { Target } from "@phosphor-icons/react";
import { ACCENT_CLASSES, ACCENT_HEX, hexToRgba } from "../../lib/colorTokens";
import { categoryMetaFor } from "../../lib/answerSections";
import { jumpToAnswerSection } from "../../lib/jumpToAnswerSection";
import type { AnswerSectionCount } from "../../lib/parseAnswerSections";

const SIZE = 180;
const CENTER = SIZE / 2;
const MAX_RADIUS = SIZE / 2 - 14;
// Floor for the smallest category so it reads as a plotted vertex, not a dot
// sitting on the origin.
const MIN_RADIUS = 18;
const RING_COUNT = 4;

function angleFor(index: number, total: number): number {
  return (Math.PI * 2 * index) / total - Math.PI / 2;
}

function pointAt(index: number, total: number, radius: number) {
  const angle = angleFor(index, total);
  return { x: CENTER + Math.cos(angle) * radius, y: CENTER + Math.sin(angle) * radius };
}

interface TooltipState {
  label: string;
  x: number;
  y: number;
  placement: "top" | "bottom";
}

export function AnswerVisualization({
  sections,
  messageId,
}: {
  sections: AnswerSectionCount[];
  messageId: string;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  const [tooltip, setTooltip] = useState<TooltipState | null>(null);
  const maxCount = useMemo(() => Math.max(...sections.map((s) => s.count), 1), [sections]);
  const n = sections.length;

  const vertices = useMemo(
    () =>
      sections.map((s, i) => {
        // Square-root scale, not linear. Category counts routinely span two
        // orders of magnitude (115 techniques vs 2 campaigns); on a linear
        // radius that pins every smaller axis to the centre and the polygon
        // degenerates into a sliver pointing at the single largest value.
        // sqrt is the standard magnitude encoding (it is what bubble charts
        // use for area) - it preserves rank order and relative weight while
        // keeping every axis legible. MIN_RADIUS guarantees a count of 1 is
        // still a visible vertex rather than a dot at the origin.
        // The exact counts are unchanged and shown verbatim in the legend.
        const ratio = maxCount > 0 ? Math.sqrt(s.count) / Math.sqrt(maxCount) : 0;
        const radius = MIN_RADIUS + ratio * (MAX_RADIUS - MIN_RADIUS);
        return { ...s, ...pointAt(i, n, radius) };
      }),
    [sections, maxCount, n]
  );

  const rings = useMemo(
    () =>
      Array.from({ length: RING_COUNT }, (_, ringIndex) => {
        const fraction = (ringIndex + 1) / RING_COUNT;
        return Array.from({ length: n }, (_, i) => pointAt(i, n, MAX_RADIUS * fraction))
          .map((p) => `${p.x},${p.y}`)
          .join(" ");
      }),
    [n]
  );

  const polygonPoints = vertices.map((p) => `${p.x},${p.y}`).join(" ");

  const showTooltip = (label: string, target: Element) => {
    const containerRect = containerRef.current?.getBoundingClientRect();
    const targetRect = target.getBoundingClientRect();
    if (!containerRect) return;
    const relativeTop = targetRect.top - containerRect.top;
    const placement = relativeTop < 96 ? "bottom" : "top";
    setTooltip({
      label,
      x: targetRect.left - containerRect.left + targetRect.width / 2,
      y: placement === "bottom" ? targetRect.bottom - containerRect.top : relativeTop,
      placement,
    });
    setHovered(label);
  };

  const hideTooltip = () => {
    setTooltip(null);
    setHovered(null);
  };

  const tooltipMeta = tooltip ? categoryMetaFor(tooltip.label) : null;
  const tooltipLeft = tooltip
    ? `clamp(140px, ${tooltip.x}px, calc(100% - 140px))`
    : undefined;

  return (
    <div
      ref={containerRef}
      className="relative mb-3 overflow-hidden rounded-xl border border-cyan/20 p-4"
      style={{
        // Instrument-panel glass: a cool sheet lit from the top-left, with a
        // bright inner top edge so it reads as a physical readout rather than a
        // flat card. No backdrop-filter - this sits inside scrolling chat and
        // would re-rasterize on every scroll frame.
        background:
          "linear-gradient(140deg, rgba(0,245,255,0.09) 0%, rgba(180,220,255,0.03) 45%, rgba(124,58,237,0.07) 100%), rgba(10,10,18,0.72)",
        boxShadow:
          "inset 0 1px 0 rgba(255,255,255,0.16), inset 0 0 40px -22px rgba(0,245,255,0.55), 0 18px 44px -30px rgba(0,245,255,0.4)",
      }}
    >
      <div className="mb-3 flex items-start gap-2">
        <Target size={14} weight="bold" className="mt-0.5 shrink-0 text-cyan" aria-hidden="true" />
        <div>
          <p className="font-mono text-[11px] font-semibold uppercase tracking-wider text-cyan">
            Threat Profile Breakdown
          </p>
          <p className="mt-0.5 font-mono text-[10px] leading-relaxed text-text-dim">
            Visual breakdown of the retrieved ATT&CK context by category.
          </p>
        </div>
      </div>

      <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-center">
        {n === 2 && (
          <div className="flex w-full shrink-0 flex-col gap-1.5 sm:w-[180px]">
            <div className="flex h-9 w-full overflow-hidden rounded-md border border-border-glow divide-x divide-border-glow">
              {vertices.map((v) => {
                const totalCount = sections.reduce((sum, s) => sum + s.count, 0);
                const pct = totalCount > 0 ? (v.count / totalCount) * 100 : 50;
                const hex = ACCENT_HEX[v.accent];
                const isHovered = hovered === v.label;
                return (
                  <button
                    type="button"
                    key={v.label}
                    style={{
                      width: `${pct}%`,
                      background: hexToRgba(hex, isHovered ? 0.55 : 0.28),
                    }}
                    className="flex min-w-0 cursor-pointer items-center justify-center font-mono text-[11px] font-semibold text-white outline-none transition-colors focus-visible:ring-2 focus-visible:ring-cyan/30"
                    aria-label={`${v.label}: ${v.count} items. Jump to section.`}
                    onMouseEnter={(e) => showTooltip(v.label, e.currentTarget)}
                    onMouseLeave={hideTooltip}
                    onFocus={(e) => showTooltip(v.label, e.currentTarget)}
                    onBlur={hideTooltip}
                    onClick={() => jumpToAnswerSection(messageId, v.label)}
                  >
                    {v.count}
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {n >= 3 && (
          <svg
            viewBox={`0 0 ${SIZE} ${SIZE}`}
            width={SIZE}
            height={SIZE}
            className="shrink-0 overflow-visible"
          >
            <defs>
              {/* Depth for the plotted shape: hot at the centre, transparent at
                  the rim, so the polygon reads as a signal return rather than a
                  flat tint. */}
              <radialGradient id="radar-fill" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor={ACCENT_HEX.cyan} stopOpacity="0.42" />
                <stop offset="55%" stopColor={ACCENT_HEX.cyan} stopOpacity="0.16" />
                <stop offset="100%" stopColor={ACCENT_HEX.cyan} stopOpacity="0.04" />
              </radialGradient>
              {/* The sweep: a cyan wedge fading to nothing behind it, rotated
                  continuously - the afterglow of a scanning radar head. */}
              <linearGradient id="radar-sweep" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor={ACCENT_HEX.cyan} stopOpacity="0" />
                <stop offset="100%" stopColor={ACCENT_HEX.cyan} stopOpacity="0.5" />
              </linearGradient>
              <filter id="radar-glow" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="2.2" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            {/* Scanning sweep, behind the data. Pure CSS rotation so it stays on
                the compositor and costs nothing per frame. */}
            <g
              className="motion-safe:animate-radar-sweep"
              style={{ transformOrigin: `${CENTER}px ${CENTER}px` }}
            >
              <path
                d={`M ${CENTER} ${CENTER} L ${CENTER + MAX_RADIUS} ${CENTER} A ${MAX_RADIUS} ${MAX_RADIUS} 0 0 0 ${
                  CENTER + MAX_RADIUS * Math.cos(-Math.PI / 3)
                } ${CENTER + MAX_RADIUS * Math.sin(-Math.PI / 3)} Z`}
                fill="url(#radar-sweep)"
                opacity={0.5}
              />
            </g>

            {/* Ping: a ring expanding from the centre out past the rim, on the
                same cadence as the sweep - the pulse a scope emits before the
                returns come back. */}
            <circle
              cx={CENTER}
              cy={CENTER}
              r={MAX_RADIUS}
              fill="none"
              stroke={ACCENT_HEX.cyan}
              strokeWidth={1}
              className="motion-safe:animate-radar-ping"
              style={{ transformOrigin: `${CENTER}px ${CENTER}px` }}
            />

            {/* Range rings */}
            <circle cx={CENTER} cy={CENTER} r={MAX_RADIUS} fill="none" stroke="rgba(0,245,255,0.14)" strokeWidth={1} />
            {rings.map((points, i) => (
              <polygon key={i} points={points} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={1} />
            ))}
            {vertices.map((v, i) => {
              const edge = pointAt(i, n, MAX_RADIUS);
              // Hovering a legend chip lights that category's axis in its own
              // accent and recedes the rest, so the two halves of the chart read
              // as one control rather than a picture beside a list.
              const isActive = hovered === v.label;
              const isMuted = hovered !== null && !isActive;
              return (
                <line
                  key={v.label}
                  x1={CENTER}
                  y1={CENTER}
                  x2={edge.x}
                  y2={edge.y}
                  stroke={isActive ? ACCENT_HEX[v.accent] : "rgba(255,255,255,0.08)"}
                  strokeWidth={isActive ? 1.75 : 1}
                  opacity={isMuted ? 0.3 : 1}
                  style={{ transition: "stroke 200ms ease, stroke-width 200ms ease, opacity 200ms ease" }}
                />
              );
            })}

            <motion.polygon
              points={polygonPoints}
              fill="url(#radar-fill)"
              stroke={ACCENT_HEX.cyan}
              strokeWidth={1.5}
              filter="url(#radar-glow)"
              initial={{ opacity: 0, scale: 0.72 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.65, ease: [0.16, 1, 0.3, 1] }}
              style={{ transformOrigin: "center" }}
            />

            {vertices.map((v) => {
              const hex = ACCENT_HEX[v.accent];
              const isHovered = hovered === v.label;
              const isMuted = hovered !== null && !isHovered;
              return (
                <g
                  key={v.label}
                  // Non-focused contacts recede rather than disappear - the
                  // shape of the profile stays readable while one axis leads.
                  opacity={isMuted ? 0.35 : 1}
                  style={{ transition: "opacity 200ms ease" }}
                >
                  {/* Contact halo - reads as a radar return, and grows on hover
                      so the whole marker responds, not just the dot. */}
                  <motion.circle
                    cx={v.x}
                    cy={v.y}
                    fill={hex}
                    initial={{ opacity: 0, r: 0 }}
                    animate={{ opacity: isHovered ? 0.3 : 0.14, r: isHovered ? 13 : 8 }}
                    transition={{ duration: 0.35, ease: "easeOut" }}
                    style={{ pointerEvents: "none" }}
                  />
                <motion.circle
                  cx={v.x}
                  cy={v.y}
                  fill={hex}
                  stroke={hex}
                  strokeOpacity={0.35}
                  initial={{ r: 0 }}
                  animate={{ r: isHovered ? 7 : 3.5 }}
                  transition={{ duration: 0.25, ease: "easeOut" }}
                  tabIndex={0}
                  role="button"
                  aria-label={`${v.label}: ${v.count} items. Jump to section.`}
                  style={{ outline: "none", cursor: "pointer" }}
                  onMouseEnter={(e) => showTooltip(v.label, e.currentTarget)}
                  onMouseLeave={hideTooltip}
                  onFocus={(e) => showTooltip(v.label, e.currentTarget)}
                  onBlur={hideTooltip}
                  onClick={() => jumpToAnswerSection(messageId, v.label)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      jumpToAnswerSection(messageId, v.label);
                    }
                  }}
                />
                </g>
              );
            })}

            <circle cx={CENTER} cy={CENTER} r={2} fill="rgba(255,255,255,0.3)" />
          </svg>
        )}

        <div className={clsx("grid w-full grid-cols-1 gap-1.5", n >= 3 ? "sm:grid-cols-2" : "sm:grid-cols-2")}>
          {sections.map((s, i) => {
            const accent = ACCENT_CLASSES[s.accent];
            const Icon = s.icon;
            const isHovered = hovered === s.label;
            return (
              <motion.button
                type="button"
                key={s.label}
                // Chips register one after another, like contacts being logged.
                // The count text itself is never animated - it renders at its
                // final value immediately so a number is never shown wrong.
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.35, delay: 0.12 + i * 0.07, ease: "easeOut" }}
                onMouseEnter={(e) => showTooltip(s.label, e.currentTarget)}
                onMouseLeave={hideTooltip}
                onFocus={(e) => showTooltip(s.label, e.currentTarget)}
                onBlur={hideTooltip}
                onClick={() => jumpToAnswerSection(messageId, s.label)}
                aria-label={`${s.label}: ${s.count} items. Jump to section.`}
                className={clsx(
                  "flex cursor-pointer items-center gap-1.5 rounded-md border px-2 py-1 text-left outline-none transition-colors",
                  "focus-visible:border-cyan/60 focus-visible:ring-2 focus-visible:ring-cyan/30",
                  isHovered ? accent.border : "border-transparent"
                )}
                style={isHovered ? { background: hexToRgba(ACCENT_HEX[s.accent], 0.08) } : undefined}
              >
                <Icon size={12} weight="bold" className={clsx("shrink-0", accent.text)} aria-hidden="true" />
                <span className="truncate font-mono text-[10px] uppercase tracking-wider text-text-mid">
                  {s.label}
                </span>
                <span className={clsx("ml-auto shrink-0 font-mono text-[10px] font-semibold", accent.text)}>
                  {s.count}
                </span>
              </motion.button>
            );
          })}
        </div>
      </div>

      {tooltip && tooltipMeta && (
        <div
          className={clsx(
            "pointer-events-none absolute z-20 max-w-[min(280px,calc(100%-24px))] -translate-x-1/2 rounded-lg border border-border-glow bg-void-raised px-3 py-2.5 shadow-[0_0_28px_-12px_rgba(0,245,255,0.75)]",
            tooltip.placement === "bottom" ? "translate-y-3" : "-translate-y-[calc(100%+12px)]"
          )}
          style={{ left: tooltipLeft, top: tooltip.y }}
        >
          <div className="mb-1 flex items-center gap-1.5">
            <tooltipMeta.icon size={12} weight="bold" className={ACCENT_CLASSES[tooltipMeta.accent].text} aria-hidden="true" />
            <p className={clsx("min-w-0 break-words font-mono text-[10px] font-semibold uppercase tracking-wider", ACCENT_CLASSES[tooltipMeta.accent].text)}>
              {tooltip.label}
            </p>
          </div>
          <p className="whitespace-normal break-words text-[11px] leading-snug text-text-mid">{tooltipMeta.description}</p>
        </div>
      )}
    </div>
  );
}
