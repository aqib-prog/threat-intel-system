/**
 * Lightweight client-side mirror of backend/log_analysis/detector.py's
 * weighted-signal approach - just enough to decide whether to grow the
 * input box's character cap before the user even submits. The backend
 * detector is the authoritative one; this only needs to agree with it
 * closely enough that a real log paste doesn't get clipped by the UI
 * before the request is even sent.
 */

const KV_PAIR_RE = /"?\b[A-Za-z_][A-Za-z0-9_]{2,40}"?\s*[:=]\s*\S+/g;
const JSON_SHAPE_RE = /^\s*[[{]/;
const PLATFORM_MARKERS_RE =
  /\b(?:EventID|ProcessName|CommandLine|ParentProcessName|TargetUserName)\s*[:=]|\btype=(?:EXECVE|SYSCALL)\b|"eventName"\s*:|"apiVersion"\s*:\s*"audit\.k8s\.io|"objectRef"\s*:/i;

const DETECTION_THRESHOLD = 5;

export function isLogShaped(text: string): boolean {
  if (!text) return false;
  let score = 0;

  const lineCount = (text.match(/\n/g)?.length ?? 0) + 1;
  if (lineCount >= 3) score += 2;
  else if (lineCount >= 2) score += 1;

  const kvCount = text.match(KV_PAIR_RE)?.length ?? 0;
  if (kvCount >= 8) score += 2;
  else if (kvCount >= 4) score += 1;

  if (text.length >= 5000) score += 2;
  else if (text.length >= 2000) score += 1;

  if (JSON_SHAPE_RE.test(text)) score += 2;
  if (PLATFORM_MARKERS_RE.test(text)) score += 2;

  return score >= DETECTION_THRESHOLD;
}
