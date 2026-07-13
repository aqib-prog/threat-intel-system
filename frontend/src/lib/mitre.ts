export const MITRE_ID_PATTERN = /\b((?:TA|T|G|S|M|DS)\d{4}(?:\.\d{3})?)\b/g;

const PREFIX_LABEL: Record<string, string> = {
  TA: "Tactic",
  T: "Technique",
  G: "Threat Group",
  S: "Software",
  M: "Mitigation",
  DS: "Data Source",
};

export function describeMitreId(id: string): string {
  const match = id.match(/^([A-Z]+)/);
  const prefix = match ? match[1] : "";
  const label = PREFIX_LABEL[prefix] ?? "MITRE ATT&CK ID";
  return `${label} · ${id}`;
}

const PREFIX_PATH: Record<string, string> = {
  TA: "tactics",
  T: "techniques",
  G: "groups",
  S: "software",
  M: "mitigations",
  DS: "datasources",
};

/** Maps a MITRE ID to its page on attack.mitre.org, e.g. "T1078.002" -> techniques/T1078/002. */
export function mitreUrl(id: string): string | null {
  const match = id.match(/^([A-Z]+)(\d{4})(?:\.(\d{3}))?$/);
  if (!match) return null;
  const [, prefix, base, sub] = match;
  const path = PREFIX_PATH[prefix];
  if (!path) return null;
  return sub
    ? `https://attack.mitre.org/${path}/${prefix}${base}/${sub}/`
    : `https://attack.mitre.org/${path}/${prefix}${base}/`;
}
