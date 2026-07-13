import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";

export function LaunchButton() {
  const navigate = useNavigate();

  return (
    <motion.button
      type="button"
      onClick={() => navigate("/chat")}
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6, delay: 0.35, ease: "easeOut" }}
      whileHover={{ scale: 1.04 }}
      whileTap={{ scale: 0.97 }}
      className="group relative isolate cursor-pointer overflow-hidden rounded-full border border-cyan/50 bg-cyan/10 px-9 py-4 font-mono text-sm font-semibold tracking-[0.15em] text-cyan motion-safe:animate-pulse-glow sm:text-base"
    >
      <span className="relative z-10 flex items-center gap-3">
        LAUNCH INTELLIGENCE
        <svg
          className="h-4 w-4 transition-transform duration-200 group-hover:translate-x-1"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          aria-hidden="true"
        >
          <path d="M5 12h14M13 6l6 6-6 6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </span>
      <span
        className="absolute inset-0 -z-10 bg-cyan opacity-0 blur-xl transition-opacity duration-300 group-hover:opacity-25"
        aria-hidden="true"
      />
    </motion.button>
  );
}
