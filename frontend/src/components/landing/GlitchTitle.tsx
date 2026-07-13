import { motion } from "framer-motion";

interface GlitchTitleProps {
  text: string;
}

export function GlitchTitle({ text }: GlitchTitleProps) {
  return (
    <motion.h1
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.7, ease: "easeOut" }}
      className="glitch-title relative select-none font-display text-[clamp(2.5rem,9vw,7rem)] font-bold leading-[0.95] tracking-tight text-white"
      data-text={text}
    >
      {text}
    </motion.h1>
  );
}
