import { useRef } from "react";
import { motion, useInView } from "framer-motion";
import { clsx } from "clsx";
import { useCountUp } from "../../hooks/useCountUp";

interface StatCardProps {
  value: number;
  label: string;
  accent: "cyan" | "green" | "purple";
  suffix?: string;
  delay?: number;
}

const ACCENT_MAP = {
  cyan: { text: "text-cyan", ring: "rgba(0,245,255,0.35)" },
  green: { text: "text-green", ring: "rgba(0,255,136,0.35)" },
  purple: { text: "text-purple", ring: "rgba(124,58,237,0.4)" },
};

export function StatCard({ value, label, accent, suffix = "", delay = 0 }: StatCardProps) {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-80px" });
  const count = useCountUp(value, 1800, inView);
  const tone = ACCENT_MAP[accent];

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, y: 24 }}
      animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.6, delay, ease: "easeOut" }}
      className="holo-card corner-brackets relative min-h-[170px] overflow-hidden rounded-xl px-6 py-7 sm:px-8 sm:py-9"
      style={{ boxShadow: `0 0 40px -12px ${tone.ring}` }}
    >
      <div
        className={clsx(
          "font-mono text-[clamp(1.5rem,4.5vw,2.75rem)] font-semibold tabular-nums leading-tight",
          tone.text
        )}
      >
        {count.toLocaleString()}
        {suffix}
      </div>
      <div className="mt-3 font-mono text-xs uppercase tracking-[0.2em] text-text-mid">
        {label}
      </div>
    </motion.div>
  );
}
