"""Detects whether an input is a raw security-log paste rather than a
natural-language question.

Deliberately separate from generation.generate's is_raw_telemetry_query(),
which only asks "does this text mention a telemetry field name?" - true for
short questions like "what does EventID=4624 mean?" that should stay on the
normal RAG path. This detector asks a stricter question: "is this actually a
log dump?" - via a weighted combination of signals (multi-line structure,
key=value density, platform-specific field markers, timestamps, raw length),
so a short question mentioning one field name never crosses the threshold.
"""

import re
from dataclasses import dataclass


# Any single short question mentioning a couple of field names should stay
# well under this bar; a genuine multi-line log paste clears it easily.
DETECTION_THRESHOLD = 5

MULTILINE_RE = re.compile(r"\n")
# Matches both plain key=value/key: value text and JSON's quoted-key shape
# ("eventName": "StopLogging") - without the optional quote, JSON logs
# (AWS CloudTrail, Kubernetes audit) under-scored and fell through to the
# question-answering path.
KV_PAIR_RE = re.compile(r'"?\b[A-Za-z_][A-Za-z0-9_]{2,40}"?\s*[:=]\s*\S+')
JSON_SHAPE_RE = re.compile(r"^\s*[\[{]")
TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|"  # ISO 8601
    r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"  # syslog "Jan 12 03:04:05"
)

WINDOWS_MARKERS = re.compile(
    r"\b(?:EventID|ProcessName|CommandLine|Image|ParentImage|ParentProcessName|"
    r"TargetUserName|LogonType|IpAddress|NewProcessName|SubjectUserName|"
    # Standard Windows Security auditing field names (Event Viewer/
    # Format-List style exports, not just Sysmon's process-creation
    # vocabulary) - Kerberos auth events (4768/4769/4771...), account
    # management, and object access events all use these.
    r"Account\s*Name|Service\s*Name|Ticket\s*Encryption\s*Type|Client\s*Address|"
    r"Pre-?Authentication\s*Type|Failure\s*Code|Logon\s*Type|Workstation\s*Name|"
    r"Object\s*Name|Access\s*Mask|Privilege\s*List|New\s*Process\s*Name|"
    r"Service\s*File\s*Name|Task\s*Name)\s*[:=]",
    re.IGNORECASE,
)
LINUX_MARKERS = re.compile(
    r"\btype=(?:EXECVE|SYSCALL|USER_CMD|LOGIN)\b|\b(?:comm|exe|auid|uid|gid|key|ses)=|"
    r"\bauditd\b",
    re.IGNORECASE,
)
AWS_MARKERS = re.compile(
    r'"eventName"\s*:|"eventSource"\s*:|"userIdentity"\s*:|"sourceIPAddress"\s*:|'
    r'"awsRegion"\s*:|"recipientAccountId"\s*:',
    re.IGNORECASE,
)
K8S_MARKERS = re.compile(
    r'"kind"\s*:\s*"Event"|"apiVersion"\s*:\s*"audit\.k8s\.io|"verb"\s*:|"objectRef"\s*:|'
    r'"resource"\s*:\s*"(?:pods|secrets|configmaps|rolebindings|clusterrolebindings)"',
    re.IGNORECASE,
)
MACOS_MARKERS = re.compile(
    r"launchagents|launchdaemons|launchctl|osascript|/library/application support/com\.apple|"
    r"\bplutil\b|\bspctl\b|\bcsrutil\b|\btccutil\b|com\.apple\.quarantine|"
    r"\bsecurity\s+(?:find-generic-password|find-internet-password|dump-keychain|unlock-keychain)|"
    r"\bchflags\b|\bxattr\b|\bhdiutil\b|\bdscl\b|\bdot_clean\b",
    re.IGNORECASE,
)

PLATFORM_MARKERS = {
    "windows": WINDOWS_MARKERS,
    "linux": LINUX_MARKERS,
    "aws": AWS_MARKERS,
    "kubernetes": K8S_MARKERS,
    "macos": MACOS_MARKERS,
}


@dataclass
class DetectionResult:
    is_raw_log: bool
    score: int
    platform: str | None
    signals: dict[str, int]


def _count_capped(pattern: re.Pattern, text: str, cap: int) -> int:
    return min(len(pattern.findall(text)), cap)


def detect(text: str) -> DetectionResult:
    text = text or ""
    signals: dict[str, int] = {}

    line_count = len(MULTILINE_RE.findall(text)) + 1
    if line_count >= 3:
        signals["multiline"] = 2
    elif line_count >= 2:
        signals["multiline"] = 1

    kv_count = len(KV_PAIR_RE.findall(text))
    if kv_count >= 8:
        signals["kv_density"] = 2
    elif kv_count >= 4:
        signals["kv_density"] = 1

    if len(text) >= 5000:
        signals["length"] = 2
    elif len(text) >= 2000:
        signals["length"] = 1

    if len(TIMESTAMP_RE.findall(text)) >= 2:
        signals["timestamps"] = 1

    if JSON_SHAPE_RE.match(text):
        signals["json_shape"] = 2

    platform_scores: dict[str, int] = {}
    for platform, pattern in PLATFORM_MARKERS.items():
        # cap=3, not 2: command-line-style platforms (macOS shell pastes
        # especially) often carry several distinct, highly-specific marker
        # hits (launchctl/osascript/security/csrutil/...) but low key=value
        # density, so under-capping this alone was leaving genuine multi-line
        # pastes just under the detection threshold.
        matched = _count_capped(pattern, text, cap=3)
        if matched:
            platform_scores[platform] = matched
            signals[f"platform_{platform}"] = matched

    score = sum(signals.values())
    # A pasted incident timeline can include multiple hosts/platforms in one
    # question (e.g. Windows DC lines followed by macOS endpoint lines). In
    # that case, choosing the single highest-scoring platform silently drops
    # valid matches from the other platform because analyzer.py only loads
    # that platform's rules. Use platform=None for mixed-platform telemetry
    # so the analyzer evaluates ALL_RULES while single-platform pastes keep
    # the narrower, faster platform-specific rule set.
    platform = None if len(platform_scores) > 1 else (max(platform_scores, key=platform_scores.get) if platform_scores else None)

    return DetectionResult(
        is_raw_log=score >= DETECTION_THRESHOLD,
        score=score,
        platform=platform,
        signals=signals,
    )
