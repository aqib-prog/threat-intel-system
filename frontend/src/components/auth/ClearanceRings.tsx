import { motion } from "framer-motion";
import { useReducedMotion } from "../../hooks/useReducedMotion";

/**
 * The auth screens' signature element: a set of concentric clearance rings that
 * physically respond to the form's real state.
 *
 * Each ring maps to one requirement - a valid address, a strong enough secret,
 * and the submission itself. A ring is dim and slowly rotating while unmet, and
 * snaps to its accent colour, closes its arc, and stops drifting the moment the
 * requirement is satisfied. The reader therefore watches the lock *actually*
 * open rather than reading a checklist of validation text.
 *
 * The arcs are drawn with stroke-dasharray on a circle, so "how much of the
 * requirement is met" is expressible as a fraction, not just met/unmet.
 */

const SIZE = 260;
const CENTER = SIZE / 2;

export interface RingState {
  /** 0-1. Drives how much of the arc is drawn. */
  progress: number;
  satisfied: boolean;
  label: string;
  hex: string;
}

function Ring({
  radius,
  state,
  index,
  reduced,
}: {
  radius: number;
  state: RingState;
  index: number;
  reduced: boolean;
}) {
  const circumference = 2 * Math.PI * radius;
  const drawn = Math.max(0.04, Math.min(1, state.progress));

  return (
    <g style={{ transformOrigin: `${CENTER}px ${CENTER}px` }}>
      {/* Track */}
      <circle
        cx={CENTER}
        cy={CENTER}
        r={radius}
        fill="none"
        stroke="rgba(255,255,255,0.06)"
        strokeWidth={1}
      />
      {/* Progress arc. Counter-rotates per ring while unmet so the assembly
          looks like it is searching, then locks square when satisfied. */}
      <motion.circle
        cx={CENTER}
        cy={CENTER}
        r={radius}
        fill="none"
        stroke={state.hex}
        strokeWidth={state.satisfied ? 2.4 : 1.6}
        strokeLinecap="round"
        strokeDasharray={`${circumference * drawn} ${circumference}`}
        style={{
          transformOrigin: `${CENTER}px ${CENTER}px`,
          filter: state.satisfied ? `drop-shadow(0 0 7px ${state.hex})` : "none",
        }}
        animate={
          reduced || state.satisfied
            ? { rotate: -90, opacity: 1 }
            : {
                rotate: index % 2 === 0 ? [0, 360] : [360, 0],
                opacity: 0.55,
              }
        }
        transition={
          state.satisfied || reduced
            ? { duration: 0.55, ease: [0.16, 1, 0.3, 1] }
            : { duration: 16 + index * 5, repeat: Infinity, ease: "linear" }
        }
      />
    </g>
  );
}

export function ClearanceRings({
  rings,
  unlocked,
}: {
  rings: RingState[];
  unlocked: boolean;
}) {
  const reduced = useReducedMotion();
  const met = rings.filter((ring) => ring.satisfied).length;

  return (
    <div className="relative flex flex-col items-center">
      <svg
        viewBox={`0 0 ${SIZE} ${SIZE}`}
        width={SIZE}
        height={SIZE}
        className="overflow-visible"
        aria-hidden="true"
      >
        {rings.map((ring, index) => (
          <Ring
            key={ring.label}
            radius={112 - index * 26}
            state={ring}
            index={index}
            reduced={reduced}
          />
        ))}

        {/* Core: dark while locked, blooming once every ring is satisfied. */}
        <motion.circle
          cx={CENTER}
          cy={CENTER}
          r={30}
          fill={unlocked ? "rgba(0,245,255,0.16)" : "rgba(255,255,255,0.03)"}
          stroke={unlocked ? "var(--color-cyan)" : "rgba(255,255,255,0.12)"}
          strokeWidth={1.4}
          animate={
            reduced
              ? undefined
              : unlocked
                ? { scale: [1, 1.09, 1] }
                : { scale: 1 }
          }
          transition={{ duration: 1.9, repeat: unlocked ? Infinity : 0, ease: "easeInOut" }}
          style={{ transformOrigin: `${CENTER}px ${CENTER}px` }}
        />

        <text
          x={CENTER}
          y={CENTER - 2}
          textAnchor="middle"
          className="fill-white font-mono"
          style={{ fontSize: "17px", fontWeight: 600 }}
        >
          {met}/{rings.length}
        </text>
        <text
          x={CENTER}
          y={CENTER + 13}
          textAnchor="middle"
          className="fill-text-dim font-mono"
          style={{ fontSize: "7.5px", letterSpacing: "0.22em" }}
        >
          CLEARED
        </text>
      </svg>

      <ul className="mt-5 w-full space-y-1.5">
        {rings.map((ring) => (
          <li key={ring.label} className="flex items-center gap-2 font-mono text-[11px]">
            <motion.span
              className="h-1.5 w-1.5 shrink-0 rounded-full"
              animate={{
                backgroundColor: ring.satisfied ? ring.hex : "rgba(255,255,255,0.18)",
                boxShadow: ring.satisfied ? `0 0 8px ${ring.hex}` : "none",
              }}
              transition={{ duration: 0.3 }}
            />
            <span className={ring.satisfied ? "text-text-mid" : "text-text-dim"}>
              {ring.label}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
