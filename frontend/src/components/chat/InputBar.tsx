import { useEffect, useMemo, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { clsx } from "clsx";
import { Lightning, PaperPlaneTilt, Terminal } from "@phosphor-icons/react";
import { isLogShaped } from "../../lib/logDetection";

const EXAMPLE_QUERIES = [
  "What techniques does APT29 use?",
  "Explain T1078 valid accounts",
  "Malware used by FIN7",
  "Detection strategies for TA0006",
];

// Single cap for both questions and log pastes - 1500 chars is enough
// headroom for either case without needing a dynamic, detection-driven limit.
const MAX_LENGTH = 1500;
const SHOW_COUNT_AT = 30; // switch the send button's icon for an exact countdown this close to the cap

const RING_SIZE = 34;
const RING_RADIUS = 15;
const RING_CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS;

interface InputBarProps {
  onSend: (query: string) => void;
  disabled: boolean;
  showChips: boolean;
}

export function InputBar({ onSend, disabled, showChips }: InputBarProps) {
  const [value, setValue] = useState("");
  const [focused, setFocused] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    const textarea = textareaRef.current;
    if (!textarea) return;

    textarea.style.height = "auto";
    textarea.style.height = `${Math.min(textarea.scrollHeight, 192)}px`;
  }, [value]);

  const detectedAsLog = useMemo(() => isLogShaped(value), [value]);
  const maxLength = MAX_LENGTH;
  const warnAt = maxLength * 0.8;

  const submit = () => {
    const trimmed = value.trim();
    if (!trimmed || disabled || trimmed.length > maxLength) return;
    onSend(trimmed);
    setValue("");
  };

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    submit();
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      submit();
    }
  };

  const pct = Math.min(1, value.length / maxLength);
  const nearLimit = value.length >= warnAt;
  const atLimit = value.length >= maxLength;

  return (
    <div className="relative shrink-0 border-t border-border-dim bg-void-raised/80 px-4 pb-4 pt-3 backdrop-blur-sm sm:px-6">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan/40 to-transparent"
      />
      <div className="mx-auto w-full max-w-5xl">
      {showChips && (
        <div className="mb-3 flex flex-wrap gap-2">
          {EXAMPLE_QUERIES.map((q) => (
            <button
              key={q}
              type="button"
              onClick={() => onSend(q)}
              disabled={disabled}
              className="group flex cursor-pointer items-center gap-1.5 rounded-full border border-border-glow bg-void-panel px-3 py-1.5 font-mono text-xs text-text-mid transition-colors hover:border-cyan/50 hover:text-cyan disabled:cursor-not-allowed disabled:opacity-50"
            >
              <Lightning size={11} weight="fill" className="text-cyan/70 group-hover:text-cyan" aria-hidden="true" />
              {q}
            </button>
          ))}
        </div>
      )}

      <AnimatePresence initial={false}>
        {detectedAsLog && (
          <motion.div
            initial={{ opacity: 0, y: 4, height: 0 }}
            animate={{ opacity: 1, y: 0, height: "auto" }}
            exit={{ opacity: 0, y: 4, height: 0 }}
            transition={{ duration: 0.2, ease: "easeOut" }}
            className="mb-2 flex w-fit items-center gap-1.5 overflow-hidden rounded border border-green/30 bg-green/10 px-1.5 py-0.5 font-mono text-[11px] uppercase tracking-wider text-green"
          >
            <Terminal size={12} weight="bold" aria-hidden="true" />
            Log input detected
          </motion.div>
        )}
      </AnimatePresence>

      <form onSubmit={handleSubmit} className="relative">
        <div
          className={clsx(
            "corner-brackets relative flex items-end gap-2 rounded-xl border bg-void-panel px-3 py-2.5 transition-shadow duration-200",
            focused
              ? // Tight ring for the edge, plus a wide soft cyan bloom so the
                // field reads as lit rather than merely outlined.
                "corner-brackets-active border-cyan/60 shadow-[0_0_0_3px_rgba(0,245,255,0.12),0_0_34px_-6px_rgba(0,245,255,0.45)]"
              : "border-border-dim"
          )}
        >
          <textarea
            ref={textareaRef}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onFocus={() => setFocused(true)}
            onBlur={() => setFocused(false)}
            onKeyDown={handleKeyDown}
            rows={1}
            maxLength={maxLength}
            placeholder="Query the knowledge graph…"
            disabled={disabled}
            className="max-h-48 min-h-9 flex-1 resize-none overflow-y-auto whitespace-pre-wrap break-words bg-transparent py-2 font-mono text-sm leading-5 text-white placeholder:text-text-dim focus:outline-none"
          />

          <div className="relative flex h-9 w-9 shrink-0 items-center justify-center">
            {value.length > 0 && (
              <svg
                viewBox={`0 0 ${RING_SIZE} ${RING_SIZE}`}
                width={RING_SIZE}
                height={RING_SIZE}
                className="absolute -rotate-90"
                aria-hidden="true"
              >
                <circle
                  cx={RING_SIZE / 2}
                  cy={RING_SIZE / 2}
                  r={RING_RADIUS}
                  fill="none"
                  stroke="rgba(255,255,255,0.08)"
                  strokeWidth={2}
                />
                <motion.circle
                  cx={RING_SIZE / 2}
                  cy={RING_SIZE / 2}
                  r={RING_RADIUS}
                  fill="none"
                  stroke={atLimit ? "#ff3366" : nearLimit ? "#ffd700" : "#00f5ff"}
                  strokeWidth={2}
                  strokeLinecap="round"
                  strokeDasharray={RING_CIRCUMFERENCE}
                  initial={false}
                  animate={{ strokeDashoffset: RING_CIRCUMFERENCE * (1 - pct) }}
                  transition={{ duration: 0.15, ease: "easeOut" }}
                  style={atLimit ? { filter: "drop-shadow(0 0 3px rgba(255,51,102,0.6))" } : undefined}
                />
              </svg>
            )}

            <motion.button
              type="submit"
              disabled={disabled || !value.trim()}
              whileTap={{ scale: 0.92 }}
              whileHover={value.trim() && !disabled ? { scale: 1.05 } : undefined}
              aria-label="Send query"
              className={clsx(
                "relative flex h-7 w-7 cursor-pointer items-center justify-center overflow-hidden rounded-lg text-cyan transition-colors disabled:cursor-not-allowed disabled:opacity-40",
                value.trim() && !disabled ? "bg-cyan/20 shadow-[0_0_16px_-2px_rgba(0,245,255,0.5)]" : "bg-cyan/15"
              )}
            >
              <AnimatePresence initial={false}>
                {value.length >= maxLength - SHOW_COUNT_AT ? (
                  <motion.span
                    key="count"
                    initial={{ opacity: 0, scale: 0.7 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.7 }}
                    transition={{ duration: 0.15 }}
                    className={clsx("font-mono text-[10px] font-semibold tabular-nums", atLimit ? "text-red" : "text-amber")}
                  >
                    {maxLength - value.length}
                  </motion.span>
                ) : (
                  <motion.span
                    key="icon"
                    initial={{ opacity: 0, scale: 0.7 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.7 }}
                    transition={{ duration: 0.15 }}
                    className="flex items-center justify-center"
                  >
                    <PaperPlaneTilt size={14} weight="fill" aria-hidden="true" />
                  </motion.span>
                )}
              </AnimatePresence>
            </motion.button>
          </div>
        </div>
      </form>
      </div>
    </div>
  );
}
