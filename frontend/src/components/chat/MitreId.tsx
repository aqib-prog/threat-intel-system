import { useState } from "react";
import { describeMitreId, mitreUrl } from "../../lib/mitre";

export function MitreId({
  id,
  authoritativeUrl,
}: {
  id: string;
  authoritativeUrl?: string | null;
}) {
  const [open, setOpen] = useState(false);
  const url = authoritativeUrl || mitreUrl(id);

  const chipClass =
    "rounded border border-amber/30 bg-amber/10 px-1 py-px font-mono font-semibold text-amber no-underline";
  const hoverHandlers = {
    onMouseEnter: () => setOpen(true),
    onMouseLeave: () => setOpen(false),
    onFocus: () => setOpen(true),
    onBlur: () => setOpen(false),
    "aria-describedby": `mitre-tip-${id}`,
  };

  return (
    <span className="relative inline-block">
      {url ? (
        <a
          href={url}
          target="_blank"
          rel="noreferrer"
          {...hoverHandlers}
          className={`${chipClass} cursor-help hover:border-amber/60 hover:bg-amber/20`}
        >
          {id}
        </a>
      ) : (
        // No authoritative URL and no safe prefix-based fallback (e.g. an
        // Analytic without its parent Detection Strategy URL): keep the visual
        // chip + tooltip, but do not render a link that would dead-end.
        <span {...hoverHandlers} tabIndex={0} className={`${chipClass} cursor-help`}>
          {id}
        </span>
      )}
      {open && (
        <span
          id={`mitre-tip-${id}`}
          role="tooltip"
          className="absolute bottom-full left-1/2 z-50 mb-2 -translate-x-1/2 whitespace-nowrap rounded-md border border-border-glow bg-void-raised px-2.5 py-1.5 font-mono text-[11px] text-white shadow-lg"
        >
          {describeMitreId(id)}
          {url ? " · view on attack.mitre.org ↗" : " · no public page"}
          <span className="absolute left-1/2 top-full -translate-x-1/2 border-4 border-transparent border-t-border-glow" />
        </span>
      )}
    </span>
  );
}
