import type { Icon } from "@phosphor-icons/react";
import { canonicalSectionLabel, categoryMetaFor } from "./answerSections";
import { humanizeLabel, type AccentColor } from "./colorTokens";
import type { NodeSource } from "./types";

export interface AnswerSectionCount {
  label: string;
  count: number;
  accent: AccentColor;
  icon: Icon;
}

const SECTION_RE = /\*\*([A-Za-z ]+):\*\*/g;
const LIST_ITEM_RE = /^\s*(?:\d+\.|[-*])\s+\S.*$/gm;
const INLINE_SECTION_RE =
  /(?:^|\n)(?:\*\*)?([A-Za-z ]+):(?:\*\*)?\s+([^\n]+?)(?=\n(?:\*\*)?[A-Za-z ]+:(?:\*\*)?\s|\n\n|$)/g;
const SECTION_LINE_RE = /^\s*(?:\*\*)?([^:\n]{3,90}?)(?:\*\*)?:\s*(.*)$/;
const MIN_VISUAL_ITEM_COUNT = 1;

// Recognized category words to look for in the sentence introducing a plain
// (non-bold-labeled) list, e.g. "...uses the following techniques on
// Windows:\n1. Foo\n2. Bar" - longest-first so "detection strategies" wins
// over a bare "detection" substring match, etc.
const INTRO_KEYWORDS = [
  "detection strategies",
  "detection strategy",
  "detections",
  "detection",
  "data components",
  "data sources",
  "also known as",
  "techniques",
  "technique",
  "mitigations",
  "mitigation",
  "campaigns",
  "campaign",
  "platforms",
  "platform",
  "analytics",
  "analytic",
  "aliases",
  "tactics",
  "tactic",
  "malware",
  "tools",
  "tool",
].sort((a, b) => b.length - a.length);

function titleCase(value: string): string {
  return value.replace(/\b\w/g, (c) => c.toUpperCase());
}

function pushUniqueSection(
  results: AnswerSectionCount[],
  label: string,
  count: number
) {
  if (count < MIN_VISUAL_ITEM_COUNT) return;
  const canonicalLabel = canonicalSectionLabel(label);
  if (!canonicalLabel) return;

  const meta = categoryMetaFor(canonicalLabel);
  if (!meta) return;
  const normalized = canonicalLabel.trim().toLowerCase();
  if (results.some((r) => r.label.trim().toLowerCase() === normalized)) return;
  results.push({ label: canonicalLabel, count, accent: meta.accent, icon: meta.icon });
}

function countInlineItems(value: string): number {
  const cleaned = value
    .replace(/\([^)]*\)/g, "")
    .replace(/\band\b/gi, ",")
    .trim();
  const commaItems = cleaned
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 1);
  return commaItems.length;
}

function countListItemsAfter(lines: string[], startIndex: number): number {
  let count = 0;

  for (let i = startIndex + 1; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    if (!trimmed) {
      if (count > 0) continue;
      continue;
    }

    if (SECTION_LINE_RE.test(trimmed) && !LIST_ITEM_RE.test(trimmed)) break;
    if (/^\s*(?:\d+\.|[-*])\s+\S/.test(line)) {
      count += 1;
      continue;
    }

    if (count > 0) break;
  }

  return count;
}

function parsePlainSections(text: string, results: AnswerSectionCount[]) {
  const lines = text.split(/\r?\n/);

  lines.forEach((line, index) => {
    const match = line.match(SECTION_LINE_RE);
    if (!match) return;

    const rawLabel = match[1].trim();
    const label = canonicalSectionLabel(rawLabel);
    if (!label) return;

    const inlineValue = match[2].trim();
    const inlineCount = inlineValue ? countInlineItems(inlineValue) : 0;
    const listCount = countListItemsAfter(lines, index);
    pushUniqueSection(results, label, Math.max(inlineCount, listCount));
  });
}

/**
 * Counts list items under each recognized category label in the raw
 * markdown response (e.g. "**Techniques:**\n1. Foo\n2. Bar" -> count 2), so
 * AnswerVisualization can chart real retrieved data instead of fabricating
 * numbers. Sections with fewer than 2 list items are skipped as not chart-worthy.
 */
export function parseAnswerSectionCounts(text: string): AnswerSectionCount[] {
  const headers = [...text.matchAll(SECTION_RE)];
  const results: AnswerSectionCount[] = [];

  for (let i = 0; i < headers.length; i++) {
    const label = headers[i][1].trim();
    const meta = categoryMetaFor(label);
    if (!meta) continue;

    const start = headers[i].index! + headers[i][0].length;
    const end = i + 1 < headers.length ? headers[i + 1].index! : text.length;
    const slice = text.slice(start, end);
    const items = slice.match(LIST_ITEM_RE);
    if (items) pushUniqueSection(results, label, items.length);
  }

  for (const match of text.matchAll(INLINE_SECTION_RE)) {
    const label = match[1].trim();
    if (!canonicalSectionLabel(label)) continue;

    const value = match[2].trim();
    const inlineCount = countInlineItems(value);
    pushUniqueSection(results, label, inlineCount);
  }

  parsePlainSections(text, results);

  return results;
}

/** Resolves a raw backend node_type ("DetectionStrategy", "DataComponent") to
 * its category metadata + a display label, sharing the same two-tier lookup
 * (direct CATEGORY_META match, then the broader CANONICAL_LABELS regex
 * fallback) the markdown-header path already gets via canonicalSectionLabel.
 * Without the humanize step first, PascalCase node_type strings never match
 * CATEGORY_META's space-separated keys and silently vanish from the chart/
 * sections even though the Sources Panel/graph render them fine (they use
 * colorTokens.ts's normalizeKey, a different and more forgiving comparison). */
function resolveNodeTypeMeta(nodeType: string): { label: string; meta: ReturnType<typeof categoryMetaFor> } {
  const humanized = humanizeLabel(nodeType);
  const direct = categoryMetaFor(humanized);
  if (direct) return { label: titleCase(humanized), meta: direct };

  const canonical = canonicalSectionLabel(humanized);
  if (canonical) {
    const meta = categoryMetaFor(canonical);
    if (meta) return { label: canonical, meta };
  }
  return { label: titleCase(humanized), meta: null };
}

export function parseNodeSectionCounts(nodes: NodeSource[] | undefined): AnswerSectionCount[] {
  if (!nodes?.length) return [];

  const counts = new Map<string, { count: number; label: string; meta: NonNullable<ReturnType<typeof categoryMetaFor>> }>();
  for (const node of nodes) {
    const rawType = node.node_type?.trim();
    if (!rawType) continue;
    const { label, meta } = resolveNodeTypeMeta(rawType);
    if (!meta) continue;
    const existing = counts.get(label);
    if (existing) existing.count += 1;
    else counts.set(label, { count: 1, label, meta });
  }

  return [...counts.values()].map(({ label, count, meta }) => ({
    label,
    count,
    accent: meta.accent,
    icon: meta.icon,
  }));
}

/**
 * Fallback for responses that don't have 2+ bold-labeled categories to
 * radar-chart: if there's exactly one bold-labeled category, use it; failing
 * that, look for a plain (unlabeled) list and infer its category from a
 * recognized keyword in the sentence that introduces it (e.g. "...following
 * techniques on Windows:"). Returns null when nothing can be confidently
 * identified, rather than guessing.
 */
export function parseSingleCategoryFallback(text: string): AnswerSectionCount | null {
  const labeled = parseAnswerSectionCounts(text);
  if (labeled.length === 1) return labeled[0];
  if (labeled.length >= 2) return null;

  const items = [...text.matchAll(LIST_ITEM_RE)];
  if (items.length < MIN_VISUAL_ITEM_COUNT) return null;

  const firstIndex = items[0].index;
  if (firstIndex === undefined) return null;

  const intro = text.slice(0, firstIndex).toLowerCase();
  const keyword = INTRO_KEYWORDS.find((kw) => intro.includes(kw));
  if (!keyword) return null;

  const label = canonicalSectionLabel(keyword);
  if (!label) return null;

  const meta = categoryMetaFor(label);
  if (!meta) return null;

  return { label, count: items.length, accent: meta.accent, icon: meta.icon };
}
