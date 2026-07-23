// Longer / multi-letter prefixes are listed before their single-letter
// counterparts (TA before T; DET/DC/DS before nothing that shadows them) so
// alternation matches the most specific prefix at each position.
export const MITRE_ID_PATTERN = /\b((?:TA|DET|DC|DS|AN|T|G|S|M|C)\d{4}(?:\.\d{3})?)\b/g;

const PREFIX_LABEL: Record<string, string> = {
  TA: "Tactic",
  T: "Technique",
  G: "Threat Group",
  S: "Software",
  M: "Mitigation",
  DS: "Data Source",
  C: "Campaign",
  DET: "Detection Strategy",
  DC: "Data Component",
  AN: "Analytic",
};

export function describeMitreId(id: string): string {
  const match = id.match(/^([A-Z]+)/);
  const prefix = match ? match[1] : "";
  const label = PREFIX_LABEL[prefix] ?? "MITRE ATT&CK ID";
  return `${label} · ${id}`;
}

// Analytics (AN####) are intentionally absent from this fallback map: their
// public URL is an anchor on a parent Detection Strategy page, which cannot be
// reconstructed from the analytic ID alone. A stored node URL can still link
// an Analytic authoritatively; without one it remains a non-clickable chip.
const PREFIX_PATH: Record<string, string> = {
  TA: "tactics",
  T: "techniques",
  G: "groups",
  S: "software",
  M: "mitigations",
  DS: "datasources",
  C: "campaigns",
  DET: "detectionstrategies",
  DC: "datacomponents",
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

/**
 * Turn an arbitrary href (usually a markdown link the backend embedded in a
 * description) into a VALID, canonical MITRE citation URL - or null.
 *
 * We do not trust the href itself: we pull the ATT&CK ID out of it and
 * regenerate the canonical page URL from that id. This means a broken/index
 * link ("attack.mitre.org/groups/" with no id), a non-MITRE link, or an id
 * type with no reconstructable standalone path (Analytics AN####) all resolve
 * to null and get no fallback citation. The link is thus derived from a real
 * retrieved id, never a raw or dead URL.
 */
export function mitreCitationUrl(href: string | null | undefined): string | null {
  if (!href) return null;
  const id = extractMitreId(href);
  return id ? mitreUrl(id) : null;
}

/** First MITRE ATT&CK id found in a string (uppercased), or null. */
export function extractMitreId(text: string | null | undefined): string | null {
  return extractMitreIds(text)[0] ?? null;
}

/** Every MITRE ATT&CK id found in a string, in source order and uppercased. */
export function extractMitreIds(text: string | null | undefined): string[] {
  if (!text) return [];
  return [...text.matchAll(/\b((?:TA|DET|DC|DS|AN|T|G|S|M|C)\d{4}(?:\.\d{3})?)\b/gi)]
    .map((match) => match[1].toUpperCase());
}
