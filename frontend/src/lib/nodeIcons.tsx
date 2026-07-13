import type { Icon } from "@phosphor-icons/react";
import {
  UserCircle,
  Bug,
  Wrench,
  Flag,
  Rocket,
  Crosshair,
  ShieldCheck,
  Broadcast,
  ChartLine,
  Database,
  Warning,
  Graph,
} from "@phosphor-icons/react";

const NODE_TYPE_ICON: Record<string, Icon> = {
  threatactor: UserCircle,
  actor: UserCircle,
  campaign: Rocket,
  tactic: Flag,
  detectionstrategy: Broadcast,
  datacomponent: Database,
  platform: Graph,
  tool: Wrench,
  mitigation: ShieldCheck,
  technique: Crosshair,
  mitreid: Crosshair,
  analytic: ChartLine,
  malware: Bug,
  cveid: Warning,
  cve: Warning,
};

function normalizeKey(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

export function iconForNodeType(nodeType: string): Icon {
  return NODE_TYPE_ICON[normalizeKey(nodeType)] ?? Graph;
}
