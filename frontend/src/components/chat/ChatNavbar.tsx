import { Link } from "react-router-dom";
import { clsx } from "clsx";
import { Logo } from "../shared/Logo";
import type { ConnectionState } from "../../lib/types";

const STATUS_CONFIG: Record<ConnectionState, { label: string; dot: string; text: string }> = {
  checking: { label: "CONNECTING…", dot: "bg-amber", text: "text-amber" },
  online: { label: "GRAPH RAG ACTIVE", dot: "bg-green", text: "text-green" },
  offline: { label: "BACKEND OFFLINE · MOCK MODE", dot: "bg-red", text: "text-red" },
};

interface ChatNavbarProps {
  connection: ConnectionState;
  onToggleFilters?: () => void;
}

export function ChatNavbar({ connection, onToggleFilters }: ChatNavbarProps) {
  const status = STATUS_CONFIG[connection];

  return (
    <header className="flex h-14 shrink-0 items-center justify-between border-b border-border-dim bg-void-raised/80 px-4 backdrop-blur-sm sm:px-6">
      <div className="flex items-center gap-3">
        {onToggleFilters && (
          <button
            type="button"
            onClick={onToggleFilters}
            aria-label="Toggle filters panel"
            className="flex h-8 w-8 cursor-pointer items-center justify-center rounded text-text-mid transition-colors hover:text-cyan lg:hidden"
          >
            <svg className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
              <path d="M4 6h16M4 12h10M4 18h6" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </button>
        )}
        <Link to="/" className="transition-opacity hover:opacity-80">
          <Logo size={24} />
        </Link>
      </div>

      <div
        className={clsx(
          "flex items-center gap-2 rounded-full border px-2.5 py-1",
          connection === "online" && "border-green/25 bg-green/5",
          connection === "offline" && "border-red/25 bg-red/5",
          connection === "checking" && "border-amber/25 bg-amber/5"
        )}
      >
        <span
          className={clsx(
            "inline-block h-1.5 w-1.5 rounded-full",
            status.dot,
            connection !== "checking" && "motion-safe:animate-pulse"
          )}
        />
        <span className={clsx("font-mono text-[11px] font-medium tracking-wider", status.text)}>
          {status.label}
        </span>
      </div>
    </header>
  );
}
