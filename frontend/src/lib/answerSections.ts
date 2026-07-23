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
  MagnifyingGlass,
  FlowArrow,
  FileText,
  Shapes,
  IdentificationBadge,
  ShieldWarning,
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
  description: { icon: FileText, accent: "blue", description: "A narrative summary of the actor or entity being profiled." },
  summary: { icon: FileText, accent: "blue", description: "A narrative summary of the actor or entity being profiled." },
  overview: { icon: Info, accent: "cyan", description: "A narrative summary of the actor or entity being profiled." },
  aliases: { icon: Fingerprint, accent: "lime", description: "Alternate names this actor is tracked under across the industry." },
  "also known as": { icon: Fingerprint, accent: "lime", description: "Alternate names this actor is tracked under across the industry." },
  // "cyan" here matches NODE_TYPE_ACCENT's actor/threatactor color in
  // colorTokens.ts (Sources Panel/graph) on purpose - this and "campaign"
  // below both use cyan in that same source of truth, not a new collision
  // introduced here.
  actor: { icon: IdentificationBadge, accent: "cyan", description: "A tracked threat group or intrusion set attributed to observed activity." },
  actors: { icon: IdentificationBadge, accent: "cyan", description: "Tracked threat groups or intrusion sets attributed to observed activity." },
  "threat actor": { icon: IdentificationBadge, accent: "cyan", description: "A tracked threat group or intrusion set attributed to observed activity." },
  "threat actors": { icon: IdentificationBadge, accent: "cyan", description: "Tracked threat groups or intrusion sets attributed to observed activity." },
  tactics: { icon: Flag, accent: "green", description: "The adversary's tactical goal — the \"why\" behind a technique, per MITRE ATT&CK (e.g. Persistence, Exfiltration)." },
  tactic: { icon: Flag, accent: "green", description: "The adversary's tactical goal — the \"why\" behind a technique, per MITRE ATT&CK." },
  techniques: { icon: Crosshair, accent: "amber", description: "How an adversary achieves a tactical goal — a specific method of attack, per MITRE ATT&CK." },
  technique: { icon: Crosshair, accent: "amber", description: "How an adversary achieves a tactical goal — a specific method of attack, per MITRE ATT&CK." },
  malware: { icon: Bug, accent: "red", description: "Malicious software the actor deploys to achieve its objectives." },
  tools: { icon: Wrench, accent: "orange", description: "Legitimate or dual-use software the actor leverages, often already present on the target system." },
  tool: { icon: Wrench, accent: "orange", description: "Legitimate or dual-use software the actor leverages, often already present on the target system." },
  campaigns: { icon: Rocket, accent: "cyan", description: "A grouped set of malicious activity carried out over a period of time, tied to a specific intent." },
  campaign: { icon: Rocket, accent: "cyan", description: "A grouped set of malicious activity carried out over a period of time, tied to a specific intent." },
  mitigations: { icon: ShieldCheck, accent: "violet", description: "Security controls or configurations that prevent a technique from succeeding." },
  mitigation: { icon: ShieldCheck, accent: "violet", description: "A security control or configuration that prevents a technique from succeeding." },
  platforms: { icon: Graph, accent: "indigo", description: "The operating systems or environments a technique applies to." },
  platform: { icon: Graph, accent: "indigo", description: "An operating system or environment a technique applies to." },
  "detection strategies": { icon: Broadcast, accent: "teal", description: "Analytic approaches for spotting a technique in telemetry." },
  "detection strategy": { icon: Broadcast, accent: "teal", description: "An analytic approach for spotting a technique in telemetry." },
  analytics: { icon: ChartLine, accent: "rose", description: "Detection logic built from log and data source patterns." },
  analytic: { icon: ChartLine, accent: "rose", description: "Detection logic built from a log or data source pattern." },
  "data sources": { icon: Database, accent: "lime", description: "Telemetry types (e.g. process creation, network traffic) used to detect a technique." },
  "data source": { icon: Database, accent: "lime", description: "A telemetry type used to detect a technique." },
  "log sources": { icon: Database, accent: "lime", description: "Telemetry types (e.g. process creation, network traffic) used to detect a technique." },
  "log source": { icon: Database, accent: "lime", description: "A telemetry type used to detect a technique." },
  "data components": { icon: Database, accent: "lime", description: "Specific fields or events within a data source used for detection." },
  "data component": { icon: Database, accent: "lime", description: "A specific field or event within a data source used for detection." },
  "strongest evidence": { icon: MagnifyingGlass, accent: "rose", description: "The specific log lines or fields that triggered each technique match, from log analysis rather than semantic search." },
  evidence: { icon: MagnifyingGlass, accent: "rose", description: "The specific log lines or fields that triggered each technique match, from log analysis rather than semantic search." },
  procedures: { icon: FlowArrow, accent: "cyan", description: "A concrete implementation or real-world example of how an actor uses a technique." },
  procedure: { icon: FlowArrow, accent: "cyan", description: "A concrete implementation or real-world example of how an actor uses a technique." },
  subtechniques: { icon: Crosshair, accent: "amber", description: "More specific variants of a parent ATT&CK technique." },
  subtechnique: { icon: Crosshair, accent: "amber", description: "A more specific variant of a parent ATT&CK technique." },
  "sub-techniques": { icon: Crosshair, accent: "amber", description: "More specific variants of a parent ATT&CK technique." },
  "sub-technique": { icon: Crosshair, accent: "amber", description: "A more specific variant of a parent ATT&CK technique." },
  "parent techniques": { icon: Crosshair, accent: "amber", description: "Parent ATT&CK techniques that contain the listed sub-techniques." },
  "parent technique": { icon: Crosshair, accent: "amber", description: "The parent ATT&CK technique that contains the sub-technique." },
  "related techniques": { icon: Crosshair, accent: "amber", description: "ATT&CK techniques related to the current answer." },
  "related technique": { icon: Crosshair, accent: "amber", description: "An ATT&CK technique related to the current answer." },
  type: { icon: Shapes, accent: "pink", description: "The ATT&CK object type for the returned item." },
  id: { icon: Info, accent: "cyan", description: "The external ATT&CK identifier for the returned item." },
  // amber, not cyan: matches NODE_TYPE_ACCENT's mitreid entry, which is
  // grouped with technique (also amber) since a bare MITRE ID most often
  // refers to a technique.
  "mitre id": { icon: Info, accent: "amber", description: "The external MITRE ATT&CK identifier for the returned item." },
  cve: { icon: ShieldWarning, accent: "red", description: "A publicly disclosed software vulnerability (Common Vulnerabilities and Exposures)." },
  "cve id": { icon: ShieldWarning, accent: "red", description: "A publicly disclosed software vulnerability (Common Vulnerabilities and Exposures)." },
};

export function categoryMetaFor(label: string): CategoryMeta | null {
  const key = label.trim().toLowerCase().replace(/:$/, "");
  return CATEGORY_META[key] ?? null;
}

const CANONICAL_LABELS: Array<[RegExp, string]> = [
  [/^(?:detection strategies?|detections?)$/i, "Detection Strategies"],
  [/^data sources?$/i, "Data Sources"],
  [/^data components?$/i, "Data Components"],
  [/^log sources?$/i, "Log Sources"],
  [/^(?:also known as|aliases?)$/i, "Aliases"],
  [/^(?:threat\s+)?actors?$/i, "Actors"],
  [/^cve(?:\s+id)?s?$/i, "Cve"],
  [/^sub[-\s]?techniques?$/i, "Subtechniques"],
  [/^parent techniques?$/i, "Parent Techniques"],
  [/^related techniques?$/i, "Related Techniques"],
  [/^techniques?$/i, "Techniques"],
  [/^procedures?$/i, "Procedures"],
  [/^mitigations?$/i, "Mitigations"],
  [/^campaigns?$/i, "Campaigns"],
  [/^platforms?$/i, "Platforms"],
  [/^analytics?$/i, "Analytics"],
  [/^tactics?$/i, "Tactics"],
  [/^malware$/i, "Malware"],
  [/^mitre id$/i, "Mitre Id"],
  [/^id$/i, "Id"],
  [/^tools?$/i, "Tools"],
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
