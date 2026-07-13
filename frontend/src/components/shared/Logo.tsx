import { clsx } from "clsx";

interface LogoProps {
  size?: number;
  showWordmark?: boolean;
  className?: string;
}

export function LogoMark({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" aria-hidden="true">
      <rect width="32" height="32" rx="7" fill="#0a0a12" stroke="#1a1c2b" />
      <g stroke="#00f5ff" strokeWidth="1.4" opacity="0.9">
        <line x1="16" y1="8" x2="8" y2="16" />
        <line x1="16" y1="8" x2="24" y2="16" />
        <line x1="8" y1="16" x2="16" y2="24" />
        <line x1="24" y1="16" x2="16" y2="24" />
        <line x1="8" y1="16" x2="24" y2="16" />
      </g>
      <circle cx="16" cy="8" r="2.3" fill="#00f5ff" />
      <circle cx="8" cy="16" r="2.3" fill="#00ff88" />
      <circle cx="24" cy="16" r="2.3" fill="#7c3aed" />
      <circle cx="16" cy="24" r="2.3" fill="#ff3366" />
    </svg>
  );
}

export function Logo({ size = 28, showWordmark = true, className }: LogoProps) {
  return (
    <div className={clsx("flex items-center gap-2.5", className)}>
      <LogoMark size={size} />
      {showWordmark && (
        <span className="font-display text-sm font-semibold tracking-[0.18em] text-white">
          THREAT<span className="text-cyan">INTEL</span>.AI
        </span>
      )}
    </div>
  );
}
