#!/usr/bin/env python3
"""Repeatable runtime benchmark for Card 5 log-analysis integration.

Each corpus is deterministic and sized to fit the API's 100,000-character
paste limit. Timing and rule-evaluation counts are kept separate so
instrumentation does not distort the latency measurement.
"""

from __future__ import annotations

import argparse
import json
import platform as host_platform
import statistics
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Callable


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BACKEND = REPO / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from log_analysis import analyzer  # noqa: E402
from log_analysis.mappings import (  # noqa: E402
    AWS_RULES,
    AWS_SIGMA_RULES,
    KUBERNETES_RULES,
    LINUX_RULES,
    LINUX_SIGMA_RULES,
    MACOS_RULES,
    MACOS_SIGMA_EXPANSION_RULES,
    MACOS_SIGMA_RULES,
    RULES_BY_PLATFORM,
    WINDOWS_RULES,
    WINDOWS_SIGMA_EXPANSION_RULES,
    WINDOWS_SIGMA_RULES,
)
from log_analysis.parser import parse_log  # noqa: E402


EVENT_COUNTS = (10, 50, 250)
DEFAULT_REPETITIONS = 9
DEFAULT_WARMUPS = 2


def windows_corpus(event_count: int) -> str:
    records: list[dict[str, Any]] = []
    for index in range(event_count):
        record = {
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "ProviderName": "Microsoft-Windows-Sysmon",
            "UtcTime": f"2026-07-16T18:{index // 60:02d}:{index % 60:02d}.000Z",
            "Image": r"C:\Program Files\Example Corp\telemetry-agent.exe",
            "CommandLine": r'"C:\Program Files\Example Corp\telemetry-agent.exe" --heartbeat',
            "ParentImage": r"C:\Windows\System32\services.exe",
            "User": r"NT AUTHORITY\SYSTEM",
            "ProcessId": 4100 + index,
        }
        records.append(record)
    # One realistic positive at the end prevents an all-negative benchmark
    # from accidentally measuring only fast failure paths.
    records[-1].update(
        {
            "Image": r"C:\Windows\System32\mshta.exe",
            "CommandLine": "mshta.exe javascript:close(new ActiveXObject('WScript.Shell').Run('calc'))",
            "ParentImage": r"C:\Windows\explorer.exe",
        }
    )
    return "\n".join(json.dumps(record, separators=(",", ":")) for record in records)


def linux_corpus(event_count: int) -> str:
    lines: list[str] = []
    for index in range(event_count):
        sequence = 10_000 + index
        timestamp = f"1721152801.{index % 1000:03d}:{sequence}"
        executable = "/usr/bin/telemetry-agent"
        command = "telemetry-agent"
        argument = "--heartbeat"
        if index == event_count - 1:
            executable = "/usr/sbin/arp"
            command = "arp"
            argument = "-a"
        lines.extend(
            (
                f'type=SYSCALL msg=audit({timestamp}): arch=c000003e syscall=59 '
                f'success=yes exit=0 pid={4100 + index} ppid=1 auid=1000 uid=1000 '
                f'comm="{command}" exe="{executable}" key="process_exec"',
                f'type=EXECVE msg=audit({timestamp}): argc=2 a0="{command}" a1="{argument}"',
                f'type=CWD msg=audit({timestamp}): cwd="/opt/example"',
            )
        )
    return "\n".join(lines)


def macos_corpus(event_count: int) -> str:
    records: list[dict[str, Any]] = []
    for index in range(event_count):
        executable = "/usr/bin/true"
        command_line = "/usr/bin/true --health-check"
        if index == event_count - 1:
            executable = "/usr/bin/base64"
            command_line = "/usr/bin/base64 -d /tmp/payload.txt"
        records.append(
            {
                "_source": {
                    "@timestamp": f"2026-07-17T00:{index // 60:02d}:{index % 60:02d}.000Z",
                    "host": {"os": {"family": "macos"}},
                    "event": {"dataset": "endpoint.events.process"},
                    "process": {
                        "pid": 4100 + index,
                        "executable": executable,
                        "command_line": command_line,
                        "parent": {"executable": "/sbin/launchd"},
                    },
                    "user": {"name": "telemetry"},
                }
            }
        )
    return "\n".join(json.dumps(record, separators=(",", ":")) for record in records)


def aws_corpus(event_count: int) -> str:
    records: list[dict[str, Any]] = []
    for index in range(event_count):
        record = {
            "eventVersion": "1.08",
            "eventTime": f"2026-07-17T01:{index // 60:02d}:{index % 60:02d}Z",
            "eventSource": "health.amazonaws.com",
            "eventName": "DescribeHealth",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "198.51.100.10",
            "userIdentity": {"type": "IAMUser", "userName": "telemetry"},
            "requestID": f"benchmark-{index}",
        }
        records.append(record)
    records[-1].update(
        {
            "eventSource": "ecs.amazonaws.com",
            "eventName": "CreateService",
            "requestParameters": {"serviceName": "benchmark-service"},
        }
    )
    return "\n".join(json.dumps(record, separators=(",", ":")) for record in records)


def kubernetes_corpus(event_count: int) -> str:
    records: list[dict[str, Any]] = []
    for index in range(event_count):
        records.append(
            {
                "apiVersion": "audit.k8s.io/v1",
                "kind": "Event",
                "auditID": f"benchmark-{index}",
                "stage": "ResponseComplete",
                "verb": "get",
                "user": {"username": "system:serviceaccount:monitoring:telemetry"},
                "objectRef": {"resource": "namespaces", "name": "default"},
                "responseStatus": {"code": 200},
            }
        )
    records[-1].update(
        {
            "verb": "create",
            "objectRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "resource": "clusterroles",
                "name": "benchmark-operator",
            },
            "responseStatus": {"code": 201},
        }
    )
    return "\n".join(json.dumps(record, separators=(",", ":")) for record in records)


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(len(ordered) * fraction + 0.999999) - 1))
    return ordered[index]


def time_call(call: Callable[[], object], repetitions: int, warmups: int) -> list[float]:
    for _ in range(warmups):
        call()
    elapsed: list[float] = []
    for _ in range(repetitions):
        started = time.perf_counter_ns()
        call()
        elapsed.append((time.perf_counter_ns() - started) / 1_000_000)
    return elapsed


def evaluation_counts(events: list[Any], platform: str) -> tuple[dict[str, int], int]:
    counts: Counter[str] = Counter()
    original = analyzer.hybrid_rule_matches

    def counted(event, raw_pattern, structured):
        matched, mode = original(event, raw_pattern, structured)
        counts[mode] += 1
        return matched, mode

    analyzer.hybrid_rule_matches = counted
    try:
        matches = analyzer.analyze(events, platform)
    finally:
        analyzer.hybrid_rule_matches = original
    return dict(sorted(counts.items())), len(matches)


LEGACY_WINDOWS_RULES = (
    WINDOWS_RULES + WINDOWS_SIGMA_RULES + WINDOWS_SIGMA_EXPANSION_RULES
)
LEGACY_LINUX_RULES = LINUX_RULES + LINUX_SIGMA_RULES
LEGACY_MACOS_RULES = MACOS_RULES + MACOS_SIGMA_RULES + MACOS_SIGMA_EXPANSION_RULES
LEGACY_AWS_RULES = AWS_RULES + AWS_SIGMA_RULES
LEGACY_KUBERNETES_RULES = KUBERNETES_RULES
CORPUS_BUILDERS = {
    "windows": windows_corpus,
    "linux": linux_corpus,
    "macos": macos_corpus,
    "aws": aws_corpus,
    "kubernetes": kubernetes_corpus,
}
CORPUS_DESCRIPTIONS = {
    "windows": "complete Windows Sysmon-style JSON records; one positive event per scenario",
    "linux": "grouped Linux auditd SYSCALL/EXECVE/CWD records; one arp -a positive event per scenario",
    "macos": "complete macOS Elastic ECS process records; one /usr/bin/base64 -d positive event per scenario",
    "aws": "complete CloudTrail NDJSON records; one ECS CreateService positive event per scenario",
    "kubernetes": "complete Kubernetes audit NDJSON records; one ClusterRole create positive event per scenario",
}
LEGACY_RULES = {
    "windows": LEGACY_WINDOWS_RULES,
    "linux": LEGACY_LINUX_RULES,
    "macos": LEGACY_MACOS_RULES,
    "aws": LEGACY_AWS_RULES,
    "kubernetes": LEGACY_KUBERNETES_RULES,
}


def benchmark_variant(
    repetitions: int,
    warmups: int,
    variant: str,
    platform: str,
    rules: list[Any],
) -> dict[str, Any]:
    original_rules = analyzer.RULES_BY_PLATFORM[platform]
    analyzer.RULES_BY_PLATFORM[platform] = rules
    corpus_builder = CORPUS_BUILDERS[platform]
    scenarios = []
    try:
        for event_count in EVENT_COUNTS:
            text = corpus_builder(event_count)
            events = parse_log(text, platform)
            expected_parsed = (
                event_count * 2 + (event_count + 1) // 3
                if platform in {"aws", "kubernetes"}
                else event_count
            )
            if len(events) != expected_parsed:
                raise RuntimeError(
                    f"expected {expected_parsed} parsed events, got {len(events)}"
                )

            parse_times = time_call(
                lambda: parse_log(text, platform), repetitions, warmups
            )
            analysis_times = time_call(
                lambda: analyzer.analyze(events, platform), repetitions, warmups
            )
            total_times = time_call(
                lambda: analyzer.analyze(parse_log(text, platform), platform),
                repetitions,
                warmups,
            )
            counts, match_count = evaluation_counts(events, platform)
            scenarios.append(
                {
                    "event_count": event_count,
                    "parsed_event_count": len(events),
                    "input_bytes": len(text.encode("utf-8")),
                    "matched_technique_count": match_count,
                    "rule_evaluations": sum(counts.values()),
                    "evaluation_modes": counts,
                    "parse_ms": {
                        "median": round(statistics.median(parse_times), 3),
                        "p95": round(percentile(parse_times, 0.95), 3),
                    },
                    "analysis_ms": {
                        "median": round(statistics.median(analysis_times), 3),
                        "p95": round(percentile(analysis_times, 0.95), 3),
                    },
                    "end_to_end_ms": {
                        "median": round(statistics.median(total_times), 3),
                        "p95": round(percentile(total_times, 0.95), 3),
                    },
                }
            )
    finally:
        analyzer.RULES_BY_PLATFORM[platform] = original_rules

    return {
        "variant": variant,
        "platform": platform,
        "runtime_inventory": {
            f"{platform}_rule_count": len(rules),
            "structured_rule_count": sum(
                rule.structured_condition is not None for rule in rules
            ),
            "raw_only_rule_count": sum(
                rule.structured_condition is None for rule in rules
            ),
        },
        "scenarios": scenarios,
    }


def benchmark(
    repetitions: int, warmups: int, variant: str, platform: str
) -> dict[str, Any]:
    common = {
        "benchmark": "Card 5 log-analysis runtime integration",
        "host": {
            "python": sys.version.split()[0],
            "system": host_platform.system(),
            "machine": host_platform.machine(),
        },
        "protocol": {
            "repetitions": repetitions,
            "warmups": warmups,
            "event_counts": list(EVENT_COUNTS),
            "api_character_limit": 100_000,
            "platform": platform,
            "corpus": CORPUS_DESCRIPTIONS[platform],
        },
    }
    variants = {
        "legacy": LEGACY_RULES[platform],
        "integrated": RULES_BY_PLATFORM[platform],
    }
    selected = variants if variant == "compare" else {variant: variants[variant]}
    results = {
        name: benchmark_variant(repetitions, warmups, name, platform, rules)
        for name, rules in selected.items()
    }
    report = common | {"variants": results}
    if variant == "compare":
        comparisons = []
        legacy = results["legacy"]["scenarios"]
        integrated = results["integrated"]["scenarios"]
        for before, after in zip(legacy, integrated, strict=True):
            before_ms = before["end_to_end_ms"]["median"]
            after_ms = after["end_to_end_ms"]["median"]
            comparisons.append(
                {
                    "event_count": before["event_count"],
                    "median_end_to_end_delta_ms": round(after_ms - before_ms, 3),
                    "median_end_to_end_change_percent": round(
                        ((after_ms / before_ms) - 1) * 100, 2
                    ),
                    "raw_regex_evaluation_delta": (
                        after["evaluation_modes"].get("raw", 0)
                        - before["evaluation_modes"].get("raw", 0)
                    ),
                    "structured_evaluation_delta": after["evaluation_modes"].get(
                        "structured", 0
                    ),
                }
            )
        report["comparison"] = comparisons
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repetitions", type=int, default=DEFAULT_REPETITIONS)
    parser.add_argument("--warmups", type=int, default=DEFAULT_WARMUPS)
    parser.add_argument(
        "--platform", choices=tuple(CORPUS_BUILDERS), default="windows"
    )
    parser.add_argument(
        "--variant",
        choices=("legacy", "integrated", "compare"),
        default="compare",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.repetitions < 1 or args.warmups < 0:
        parser.error("repetitions must be positive and warmups non-negative")
    report = benchmark(args.repetitions, args.warmups, args.variant, args.platform)
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
