import { useMemo } from "react";
import { motion } from "framer-motion";
import { useReducedMotion } from "../../hooks/useReducedMotion";
import { MOCK_MITRE_BADGES } from "../../lib/mock";

const COLORS = ["#00f5ff", "#00ff88", "#7c3aed", "#ffd700"];

interface Badge {
  id: string;
  text: string;
  top: number;
  duration: number;
  delay: number;
  color: string;
  size: number;
}

export function MitreBadges() {
  const reducedMotion = useReducedMotion();

  const badges = useMemo<Badge[]>(
    () =>
      MOCK_MITRE_BADGES.map((text, i) => ({
        id: `${text}-${i}`,
        text,
        // Confined to thin bands at the very top/bottom of the viewport so
        // badges drift along the edges instead of crossing the hero text,
        // launch button, and stat cards in the content column.
        top: i % 2 === 0 ? 2 + ((i * 13) % 9) : 89 + ((i * 13) % 9),
        duration: 26 + (i % 5) * 6,
        delay: -(i * 3.1),
        color: COLORS[i % COLORS.length],
        size: i % 3 === 0 ? 13 : 11,
      })),
    []
  );

  if (reducedMotion) return null;

  return (
    <div className="pointer-events-none absolute inset-0 z-[1] overflow-hidden">
      {badges.map((b) => (
        <motion.div
          key={b.id}
          className="absolute whitespace-nowrap rounded-full border px-2.5 py-1 font-mono opacity-0"
          style={{
            top: `${b.top}%`,
            borderColor: `${b.color}55`,
            color: b.color,
            fontSize: b.size,
            background: "rgba(5,5,8,0.55)",
            boxShadow: `0 0 12px ${b.color}33`,
          }}
          initial={{ x: "-8vw", opacity: 0 }}
          animate={{ x: "110vw", opacity: [0, 0.7, 0.7, 0] }}
          transition={{
            duration: b.duration,
            delay: b.delay,
            repeat: Infinity,
            ease: "linear",
          }}
        >
          {b.text}
        </motion.div>
      ))}
    </div>
  );
}
