export type AccentColor =
  | "cyan"
  | "green"
  | "purple"
  | "amber"
  | "red"
  | "blue"
  | "pink"
  | "teal"
  | "orange"
  | "violet"
  | "rose"
  | "lime"
  | "indigo";

interface AccentClasses {
  text: string;
  border: string;
  bg: string;
  dot: string;
  bar: string;
}

export const ACCENT_HEX: Record<AccentColor, string> = {
  cyan: "#00f5ff",
  green: "#00ff88",
  purple: "#7c3aed",
  amber: "#ffd700",
  red: "#ff3366",
  blue: "#3b82f6",
  pink: "#ff4fd8",
  teal: "#14f1c3",
  orange: "#ff9f1c",
  violet: "#a855f7",
  rose: "#fb7185",
  lime: "#bef264",
  indigo: "#818cf8",
};

export function hexToRgba(hex: string, alpha: number): string {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

export const ACCENT_CLASSES: Record<AccentColor, AccentClasses> = {
  cyan: {
    text: "text-cyan",
    border: "border-cyan/35",
    bg: "bg-cyan/10",
    dot: "bg-cyan",
    bar: "bg-cyan",
  },
  green: {
    text: "text-green",
    border: "border-green/35",
    bg: "bg-green/10",
    dot: "bg-green",
    bar: "bg-green",
  },
  purple: {
    text: "text-purple",
    border: "border-purple/35",
    bg: "bg-purple/10",
    dot: "bg-purple",
    bar: "bg-purple",
  },
  amber: {
    text: "text-amber",
    border: "border-amber/35",
    bg: "bg-amber/10",
    dot: "bg-amber",
    bar: "bg-amber",
  },
  red: {
    text: "text-red",
    border: "border-red/35",
    bg: "bg-red/10",
    dot: "bg-red",
    bar: "bg-red",
  },
  blue: {
    text: "text-blue",
    border: "border-blue/35",
    bg: "bg-blue/10",
    dot: "bg-blue",
    bar: "bg-blue",
  },
  pink: {
    text: "text-pink",
    border: "border-pink/35",
    bg: "bg-pink/10",
    dot: "bg-pink",
    bar: "bg-pink",
  },
  teal: {
    text: "text-teal",
    border: "border-teal/35",
    bg: "bg-teal/10",
    dot: "bg-teal",
    bar: "bg-teal",
  },
  orange: {
    text: "text-orange",
    border: "border-orange/35",
    bg: "bg-orange/10",
    dot: "bg-orange",
    bar: "bg-orange",
  },
  violet: {
    text: "text-violet",
    border: "border-violet/35",
    bg: "bg-violet/10",
    dot: "bg-violet",
    bar: "bg-violet",
  },
  rose: {
    text: "text-rose",
    border: "border-rose/35",
    bg: "bg-rose/10",
    dot: "bg-rose",
    bar: "bg-rose",
  },
  lime: {
    text: "text-lime",
    border: "border-lime/35",
    bg: "bg-lime/10",
    dot: "bg-lime",
    bar: "bg-lime",
  },
  indigo: {
    text: "text-indigo",
    border: "border-indigo/35",
    bg: "bg-indigo/10",
    dot: "bg-indigo",
    bar: "bg-indigo",
  },
};

// Keys are normalized (lowercased, non-alphanumeric stripped) so both
// snake_case filter keys ("detection_strategy") and the PascalCase
// node_type strings the pipeline actually returns ("DetectionStrategy",
// see orchestration/pipeline.py's CASE statement) resolve to the same entry.
const NODE_TYPE_ACCENT: Record<string, AccentColor> = {
  threatactor: "cyan",
  actor: "cyan",
  campaign: "cyan",
  tactic: "green",
  detectionstrategy: "teal",
  datacomponent: "lime",
  platform: "indigo",
  tool: "orange",
  mitigation: "violet",
  technique: "amber",
  mitreid: "amber",
  analytic: "rose",
  malware: "red",
  cveid: "red",
  cve: "red",
};

function normalizeKey(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

export function accentForNodeType(nodeType: string): AccentColor {
  return NODE_TYPE_ACCENT[normalizeKey(nodeType)] ?? "cyan";
}

export function accentForFilterKey(key: string): AccentColor {
  return NODE_TYPE_ACCENT[normalizeKey(key)] ?? "cyan";
}

/** "DetectionStrategy" -> "Detection Strategy", "threat_actor" -> "threat actor" */
export function humanizeLabel(value: string): string {
  return value
    .replace(/_/g, " ")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .trim();
}
