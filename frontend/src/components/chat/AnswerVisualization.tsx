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
        const radius = (s.count / maxCount) * MAX_RADIUS;
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
    <div ref={containerRef} className="relative mb-3 rounded-lg border border-border-glow bg-void-raised/50 p-4">
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
            {rings.map((points, i) => (
              <polygon key={i} points={points} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={1} />
            ))}
            {vertices.map((v, i) => {
              const edge = pointAt(i, n, MAX_RADIUS);
              return <line key={v.label} x1={CENTER} y1={CENTER} x2={edge.x} y2={edge.y} stroke="rgba(255,255,255,0.08)" strokeWidth={1} />;
            })}

            <motion.polygon
              points={polygonPoints}
              fill={hexToRgba(ACCENT_HEX.cyan, 0.16)}
              stroke={ACCENT_HEX.cyan}
              strokeWidth={1.5}
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.5, ease: "easeOut" }}
              style={{ transformOrigin: "center" }}
            />

            {vertices.map((v) => {
              const hex = ACCENT_HEX[v.accent];
              const isHovered = hovered === v.label;
              return (
                <motion.circle
                  key={v.label}
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
              );
            })}

            <circle cx={CENTER} cy={CENTER} r={2} fill="rgba(255,255,255,0.3)" />
          </svg>
        )}

        <div className={clsx("grid w-full grid-cols-1 gap-1.5", n >= 3 ? "sm:grid-cols-2" : "sm:grid-cols-2")}>
          {sections.map((s) => {
            const accent = ACCENT_CLASSES[s.accent];
            const Icon = s.icon;
            const isHovered = hovered === s.label;
            return (
              <button
                type="button"
                key={s.label}
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
              </button>
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
