import type { Icon } from "@phosphor-icons/react";
import {
  Info,
  Fingerprint,
  Flag,
  Crosshair,
  Bug,
  Wrench,
  Rocket,
  ShieldCheck,
  Graph,
  Broadcast,
  ChartLine,
  Database,
} from "@phosphor-icons/react";
import type { AccentColor } from "./colorTokens";

interface CategoryMeta {
  icon: Icon;
  accent: AccentColor;
  /** Short MITRE ATT&CK glossary-style definition shown on hover. */
  description: string;
}

// Keyed on the bold lead-in labels the generation LLM uses to open a
// section (e.g. "**Tactics:** ..."), not on backend node_type strings -
// intentionally separate from lib/nodeIcons.tsx's mapping.
const CATEGORY_META: Record<string, CategoryMeta> = {
  description: { icon: Info, accent: "cyan", description: "A narrative summary of the actor or entity being profiled." },
  summary: { icon: Info, accent: "cyan", description: "A narrative summary of the actor or entity being profiled." },
  overview: { icon: Info, accent: "cyan", description: "A narrative summary of the actor or entity being profiled." },
  aliases: { icon: Fingerprint, accent: "cyan", description: "Alternate names this actor is tracked under across the industry." },
  "also known as": { icon: Fingerprint, accent: "cyan", description: "Alternate names this actor is tracked under across the industry." },
  tactics: { icon: Flag, accent: "green", description: "The adversary's tactical goal — the \"why\" behind a technique, per MITRE ATT&CK (e.g. Persistence, Exfiltration)." },
  tactic: { icon: Flag, accent: "green", description: "The adversary's tactical goal — the \"why\" behind a technique, per MITRE ATT&CK." },
  techniques: { icon: Crosshair, accent: "amber", description: "How an adversary achieves a tactical goal — a specific method of attack, per MITRE ATT&CK." },
  technique: { icon: Crosshair, accent: "amber", description: "How an adversary achieves a tactical goal — a specific method of attack, per MITRE ATT&CK." },
  malware: { icon: Bug, accent: "red", description: "Malicious software the actor deploys to achieve its objectives." },
  tools: { icon: Wrench, accent: "purple", description: "Legitimate or dual-use software the actor leverages, often already present on the target system." },
  tool: { icon: Wrench, accent: "purple", description: "Legitimate or dual-use software the actor leverages, often already present on the target system." },
  campaigns: { icon: Rocket, accent: "cyan", description: "A grouped set of malicious activity carried out over a period of time, tied to a specific intent." },
  campaign: { icon: Rocket, accent: "cyan", description: "A grouped set of malicious activity carried out over a period of time, tied to a specific intent." },
  mitigations: { icon: ShieldCheck, accent: "purple", description: "Security controls or configurations that prevent a technique from succeeding." },
  mitigation: { icon: ShieldCheck, accent: "purple", description: "A security control or configuration that prevents a technique from succeeding." },
  platforms: { icon: Graph, accent: "purple", description: "The operating systems or environments a technique applies to." },
  platform: { icon: Graph, accent: "purple", description: "An operating system or environment a technique applies to." },
  "detection strategies": { icon: Broadcast, accent: "green", description: "Analytic approaches for spotting a technique in telemetry." },
  "detection strategy": { icon: Broadcast, accent: "green", description: "An analytic approach for spotting a technique in telemetry." },
  analytics: { icon: ChartLine, accent: "amber", description: "Detection logic built from log and data source patterns." },
  analytic: { icon: ChartLine, accent: "amber", description: "Detection logic built from a log or data source pattern." },
  "data sources": { icon: Database, accent: "green", description: "Telemetry types (e.g. process creation, network traffic) used to detect a technique." },
  "data components": { icon: Database, accent: "green", description: "Specific fields or events within a data source used for detection." },
};

export function categoryMetaFor(label: string): CategoryMeta | null {
  const key = label.trim().toLowerCase().replace(/:$/, "");
  return CATEGORY_META[key] ?? null;
}

const CANONICAL_LABELS: Array<[RegExp, string]> = [
  [/\bdetection strategies?\b|\bdetections?\b|\bdetect(?:ion)?\b/i, "Detection Strategies"],
  [/\bdata sources?\b/i, "Data Sources"],
  [/\bdata components?\b/i, "Data Components"],
  [/\balso known as\b|\balias(?:es)?\b/i, "Aliases"],
  [/\btechniques?\b/i, "Techniques"],
  [/\bmitigations?\b/i, "Mitigations"],
  [/\bcampaigns?\b/i, "Campaigns"],
  [/\bplatforms?\b/i, "Platforms"],
  [/\banalytics?\b/i, "Analytics"],
  [/\btactics?\b/i, "Tactics"],
  [/\bmalware\b/i, "Malware"],
  [/\btools?\b/i, "Tools"],
];

function titleCase(value: string): string {
  return value.replace(/\b\w/g, (c) => c.toUpperCase());
}

export function canonicalSectionLabel(rawLabel: string): string | null {
  const direct = rawLabel.trim().replace(/\*+/g, "").replace(/:$/, "");
  if (categoryMetaFor(direct)) return titleCase(direct);

  const match = CANONICAL_LABELS.find(([pattern]) => pattern.test(direct));
  return match ? match[1] : null;
}

/** Scoped to a message id so identical category labels across different messages don't collide as duplicate DOM ids. */
export function sectionId(messageId: string, label: string): string {
  const slug = label.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-");
  return `answer-section-${messageId}-${slug}`;
}
