import { useState } from "react";
import { describeMitreId, mitreUrl } from "../../lib/mitre";

export function MitreId({ id }: { id: string }) {
  const [open, setOpen] = useState(false);
  const url = mitreUrl(id);

  return (
    <span className="relative inline-block">
      <a
        href={url ?? undefined}
        target="_blank"
        rel="noreferrer"
        aria-describedby={`mitre-tip-${id}`}
        onMouseEnter={() => setOpen(true)}
        onMouseLeave={() => setOpen(false)}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        className="cursor-help rounded border border-amber/30 bg-amber/10 px-1 py-px font-mono font-semibold text-amber no-underline hover:border-amber/60 hover:bg-amber/20"
      >
        {id}
      </a>
      {open && (
        <span
          id={`mitre-tip-${id}`}
          role="tooltip"
          className="absolute bottom-full left-1/2 z-50 mb-2 -translate-x-1/2 whitespace-nowrap rounded-md border border-border-glow bg-void-raised px-2.5 py-1.5 font-mono text-[11px] text-white shadow-lg"
        >
          {describeMitreId(id)} · view on attack.mitre.org ↗
          <span className="absolute left-1/2 top-full -translate-x-1/2 border-4 border-transparent border-t-border-glow" />
        </span>
      )}
    </span>
  );
}
