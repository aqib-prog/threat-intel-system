import { clsx } from "clsx";
import { ACCENT_CLASSES, accentForFilterKey, humanizeLabel } from "../../lib/colorTokens";
import { iconForNodeType } from "../../lib/nodeIcons";

function formatFilterValue(value: unknown): string {
  if (Array.isArray(value)) return value.join(", ");
  if (value === null || value === undefined) return "—";
  return String(value);
}

export function FilterList({ filters }: { filters: Record<string, unknown> }) {
  const entries = Object.entries(filters);

  if (entries.length === 0) {
    return (
      <p className="font-mono text-xs leading-relaxed text-text-dim">
        No filters extracted yet. Ask about an actor, technique, tactic, or
        platform to see them appear here.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <p className="font-mono text-[10px] leading-relaxed text-text-dim">
        Auto-detected from your last question — read-only, shapes how the graph was searched.
      </p>
      <ul className="flex flex-col gap-2.5">
        {entries.map(([key, value]) => {
          const accent = ACCENT_CLASSES[accentForFilterKey(key)];
          const Icon = iconForNodeType(key);
          return (
            <li key={key} className="flex flex-col gap-1">
              <span className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-text-dim">
                <Icon className={accent.text} size={11} weight="bold" aria-hidden="true" />
                {humanizeLabel(key)}
              </span>
              <span
                className={clsx(
                  "w-fit max-w-full cursor-default truncate rounded-md border px-2 py-1 font-mono text-xs",
                  accent.border,
                  accent.bg,
                  accent.text
                )}
                title={formatFilterValue(value)}
              >
                {formatFilterValue(value)}
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
