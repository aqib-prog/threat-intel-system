import type { AnswerPresentation } from "./types";

function sameLabel(left: string, right: string): boolean {
  return left.trim().replace(/:$/, "").toLowerCase() ===
    right.trim().replace(/:$/, "").toLowerCase();
}

/** Convert backend-owned presentation data into canonical Markdown markers.
 *
 * The frontend does not discover section boundaries here: it receives the
 * labels, grouping, headings, and Markdown content from the API. Canonical
 * markers only feed the existing visual card renderer.
 */
export function markdownFromAnswerPresentation(
  fallback: string,
  presentation?: AnswerPresentation | null,
): string {
  if (!presentation || presentation.blocks.length === 0) return fallback;

  const parts: string[] = [];
  if (presentation.preamble.trim()) parts.push(presentation.preamble.trim());

  for (const block of presentation.blocks) {
    const entries = block.entries
      .map((entry) => {
        const content: string[] = [];
        if (entry.heading.trim() && !sameLabel(entry.heading, block.label)) {
          content.push(entry.heading.trim());
        }
        if (entry.markdown.trim()) content.push(entry.markdown.trim());
        return content.join("\n\n");
      })
      .filter(Boolean);
    if (entries.length === 0) continue;
    parts.push(`**${block.label}:**\n\n${entries.join("\n\n---\n\n")}`);
  }

  return parts.length > 0 ? parts.join("\n\n") : fallback;
}
