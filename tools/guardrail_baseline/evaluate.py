#!/usr/bin/env python3
"""Card 6 Part A step 1: measure the unchanged production guardrail."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BACKEND = REPO / "backend"
MANIFEST_PATH = HERE / "source_manifest.json"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from retrieval import guardrail as production  # noqa: E402


class BaselineError(RuntimeError):
    pass


@dataclass(frozen=True)
class Case:
    corpus: str
    split: str
    source_id: str
    category: str
    functional_category: str | None
    prompt: str

    @property
    def prompt_sha256(self) -> str:
        return hashlib.sha256(self.prompt.encode("utf-8")).hexdigest()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git_head(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True
    )
    if result.returncode:
        raise BaselineError(f"not a Git checkout: {root}")
    return result.stdout.strip()


def verify_checkout(root: Path, expected_commit: str, label: str) -> None:
    actual = git_head(root)
    if actual != expected_commit:
        raise BaselineError(f"{label} commit {actual}, expected {expected_commit}")
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=root,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    if status:
        raise BaselineError(f"{label} checkout is dirty")


def checked_csv(path: Path, expected_hash: str, expected_rows: int) -> list[dict[str, str]]:
    if sha256(path) != expected_hash:
        raise BaselineError(f"source hash mismatch: {path}")
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != expected_rows:
        raise BaselineError(f"{path} has {len(rows)} rows, expected {expected_rows}")
    return rows


def load_cases(
    harmbench_root: Path,
    jailbreakbench_root: Path,
    jbb_behaviors_root: Path,
) -> tuple[list[Case], dict[str, Any]]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    hb = manifest["harmbench"]
    jbb_code = manifest["jailbreakbench_code"]
    jbb = manifest["jailbreakbench_behaviors"]
    verify_checkout(harmbench_root, hb["commit"], "HarmBench")
    verify_checkout(jailbreakbench_root, jbb_code["commit"], "JailbreakBench")
    verify_checkout(jbb_behaviors_root, jbb["commit"], "JBB-Behaviors")

    cases: list[Case] = []
    hb_path = harmbench_root / hb["path"]
    for row in checked_csv(hb_path, hb["sha256"], hb["expected_rows"]):
        prompt = row["Behavior"]
        if row["ContextString"]:
            # HarmBench's DirectRequest implementation constructs contextual
            # prompts exactly this way. No benchmark wording is rewritten.
            prompt = f'{row["ContextString"]}\n\n---\n\n{prompt}'
        cases.append(
            Case(
                corpus="harmbench",
                split="harmful",
                source_id=row["BehaviorID"],
                category=row["SemanticCategory"],
                functional_category=row["FunctionalCategory"],
                prompt=prompt,
            )
        )

    for split, path_key, hash_key in (
        ("harmful", "harmful_path", "harmful_sha256"),
        ("benign", "benign_path", "benign_sha256"),
    ):
        path = jbb_behaviors_root / jbb[path_key]
        for row in checked_csv(path, jbb[hash_key], jbb["expected_rows_per_split"]):
            cases.append(
                Case(
                    corpus="jailbreakbench",
                    split=split,
                    source_id=row["Behavior"],
                    category=row["Category"],
                    functional_category=None,
                    prompt=row["Goal"],
                )
            )
    return cases, manifest


def evaluate_case(case: Case) -> dict[str, Any]:
    start = time.perf_counter()
    blacklist = production.check_blacklist(case.prompt)
    llm_called = False
    fail_open = False
    reason = None
    if not blacklist["allowed"]:
        allowed = False
        layer = "blacklist"
        decision_category = blacklist.get("category", "blocked")
    elif production.has_cybersecurity_signal(case.prompt):
        allowed = True
        layer = "cybersecurity_fast_allow"
        decision_category = None
    else:
        llm_called = True
        llm_result = production.check_llm_guardrail(case.prompt)
        allowed = bool(llm_result["allowed"])
        reason = str(llm_result.get("reason", ""))
        fail_open = allowed and reason.startswith("Could not parse")
        layer = "llm_fail_open" if fail_open else "llm_classifier"
        decision_category = None if allowed else "llm_blocked"
    elapsed = time.perf_counter() - start
    return {
        "corpus": case.corpus,
        "split": case.split,
        "source_id": case.source_id,
        "category": case.category,
        "functional_category": case.functional_category,
        "prompt_sha256": case.prompt_sha256,
        "allowed": allowed,
        "blocked": not allowed,
        "layer": layer,
        "decision_category": decision_category,
        "llm_called": llm_called,
        "llm_fail_open": fail_open,
        "llm_reason": reason,
        "elapsed_seconds": elapsed,
    }


def rate(blocked: int, total: int) -> float:
    return round(blocked / total, 6) if total else 0.0


def grouped_metrics(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        value = row.get(key)
        groups[str(value if value is not None else "none")].append(row)
    return {
        name: {
            "total": len(items),
            "blocked": sum(item["blocked"] for item in items),
            "block_rate": rate(sum(item["blocked"] for item in items), len(items)),
        }
        for name, items in sorted(groups.items())
    }


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def latency_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    values = [float(row["elapsed_seconds"]) for row in rows]
    return {
        "count": len(values),
        "total_seconds": round(sum(values), 6),
        "mean_seconds": round(statistics.fmean(values), 6) if values else 0.0,
        "p50_seconds": round(percentile(values, 0.50), 6),
        "p95_seconds": round(percentile(values, 0.95), 6),
        "p99_seconds": round(percentile(values, 0.99), 6),
        "max_seconds": round(max(values), 6) if values else 0.0,
    }


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    harmful = [row for row in rows if row["split"] == "harmful"]
    benign = [row for row in rows if row["split"] == "benign"]
    unique_harmful = {row["prompt_sha256"]: row for row in harmful}

    def totals(items: list[dict[str, Any]]) -> dict[str, Any]:
        blocked = sum(row["blocked"] for row in items)
        return {"total": len(items), "blocked": blocked, "block_rate": rate(blocked, len(items))}

    by_corpus = {}
    for corpus in sorted({row["corpus"] for row in rows}):
        corpus_rows = [row for row in rows if row["corpus"] == corpus]
        by_corpus[corpus] = {
            split: totals([row for row in corpus_rows if row["split"] == split])
            for split in sorted({row["split"] for row in corpus_rows})
        }
    return {
        "harmful_source_weighted": totals(harmful),
        "harmful_unique_prompts": totals(list(unique_harmful.values())),
        # This is intentionally not called a false-positive rate. JBB benign
        # includes many valid general-domain prompts that this product's
        # cybersecurity-only scope is designed to reject.
        "jbb_benign_rejection": totals(benign),
        "by_corpus": by_corpus,
        "by_category": grouped_metrics(rows, "category"),
        "harmbench_by_functional_category": grouped_metrics(
            [row for row in rows if row["corpus"] == "harmbench"],
            "functional_category",
        ),
        "decision_layers": dict(sorted(Counter(row["layer"] for row in rows).items())),
        "llm_call_count": sum(row["llm_called"] for row in rows),
        "llm_fail_open_count": sum(row["llm_fail_open"] for row in rows),
        "latency_all": latency_metrics(rows),
        "latency_llm_calls": latency_metrics([row for row in rows if row["llm_called"]]),
    }


def model_metadata() -> dict[str, Any]:
    try:
        response = production.ollama.list()
        payload = response.model_dump() if hasattr(response, "model_dump") else response
        models = payload.get("models", []) if isinstance(payload, dict) else []
        for model in models:
            item = model.model_dump() if hasattr(model, "model_dump") else model
            name = str(item.get("model") or item.get("name") or "")
            if name in {"llama3.1", "llama3.1:latest"}:
                return {
                    "configured_name": "llama3.1",
                    "resolved_name": name,
                    "digest": item.get("digest"),
                    "size": item.get("size"),
                }
    except Exception as exc:  # metadata must not change production fail-open behavior
        return {"configured_name": "llama3.1", "metadata_error": type(exc).__name__}
    return {"configured_name": "llama3.1", "resolved_name": None}


def render_markdown(report: dict[str, Any]) -> str:
    metrics = report["metrics"]
    harmful = metrics["harmful_source_weighted"]
    unique = metrics["harmful_unique_prompts"]
    benign = metrics["jbb_benign_rejection"]
    lines = [
        "# Card 6 Part A step 1: current-guardrail baseline",
        "",
        f"Status: **MEASURED** ({report['measured_at']})",
        "",
        "No guardrail behavior was changed for this measurement. The harness calls the",
        "production blacklist, cybersecurity fast-allow, and Ollama `llama3.1` classifier",
        "in the same order as `guardrail()`.",
        "",
        "## Headline results",
        "",
        "| Measure | Blocked | Total | Rate |",
        "| --- | ---: | ---: | ---: |",
        f"| Harmful prompts, source-weighted | {harmful['blocked']} | {harmful['total']} | {harmful['block_rate']:.1%} |",
        f"| Harmful prompts, exact-text deduplicated | {unique['blocked']} | {unique['total']} | {unique['block_rate']:.1%} |",
        f"| JailbreakBench benign rejection | {benign['blocked']} | {benign['total']} | {benign['block_rate']:.1%} |",
        "",
        "JailbreakBench benign rejection is **not** treated as a product false-positive",
        "rate: its benign split contains many general-domain requests that this",
        "cybersecurity-only assistant intentionally rejects.",
        "",
        "## Corpus results",
        "",
        "| Corpus / split | Blocked | Total | Rate |",
        "| --- | ---: | ---: | ---: |",
    ]
    for corpus, splits in metrics["by_corpus"].items():
        for split, values in splits.items():
            lines.append(
                f"| {corpus} / {split} | {values['blocked']} | {values['total']} | {values['block_rate']:.1%} |"
            )
    lines += [
        "",
        "## Layer and reliability observations",
        "",
        f"- Decision layers: `{json.dumps(metrics['decision_layers'], sort_keys=True)}`",
        f"- Ollama classifier calls: **{metrics['llm_call_count']}**",
        f"- Classifier fail-open results: **{metrics['llm_fail_open_count']}**",
        f"- Total measured guardrail time: **{metrics['latency_all']['total_seconds']:.3f}s**",
        f"- LLM-call p50 / p95: **{metrics['latency_llm_calls']['p50_seconds']:.3f}s / {metrics['latency_llm_calls']['p95_seconds']:.3f}s**",
        "",
        "## Scope and provenance",
        "",
        "- HarmBench input: all 400 canonical text behaviors. Contextual rows use",
        "  HarmBench's own DirectRequest context/separator/behavior construction.",
        "- JailbreakBench input: all 100 harmful and 100 benign `Goal` strings verbatim.",
        "- Reports contain prompt hashes and benchmark identifiers, not prompt text.",
        "- Source commits and file hashes are pinned in `source_manifest.json`.",
        "",
        "This is a behavior-rejection baseline, not a guarantee of jailbreak robustness:",
        "these files are direct-request behavior sets, not every generated adversarial",
        "suffix or submitted jailbreak artifact supported by the full frameworks.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--harmbench-root", type=Path, required=True)
    parser.add_argument("--jailbreakbench-root", type=Path, required=True)
    parser.add_argument("--jbb-behaviors-root", type=Path, required=True)
    parser.add_argument("--report-json", type=Path, default=HERE / "baseline_report.json")
    parser.add_argument("--report-md", type=Path, default=HERE / "baseline_report.md")
    parser.add_argument("--checkpoint-every", type=int, default=10)
    args = parser.parse_args()
    if args.checkpoint_every < 1:
        raise BaselineError("--checkpoint-every must be positive")

    cases, manifest = load_cases(
        args.harmbench_root.resolve(),
        args.jailbreakbench_root.resolve(),
        args.jbb_behaviors_root.resolve(),
    )
    partial_path = args.report_json.with_suffix(".partial.json")
    completed: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    if partial_path.exists():
        partial = json.loads(partial_path.read_text(encoding="utf-8"))
        for row in partial.get("cases", []):
            completed[
                (
                    row["corpus"],
                    row["split"],
                    row["source_id"],
                    row["prompt_sha256"],
                )
            ] = row

    started = time.perf_counter()
    results: list[dict[str, Any]] = []
    for index, case in enumerate(cases, start=1):
        key = (case.corpus, case.split, case.source_id, case.prompt_sha256)
        row = completed.get(key) or evaluate_case(case)
        results.append(row)
        if index % args.checkpoint_every == 0 or index == len(cases):
            partial_path.parent.mkdir(parents=True, exist_ok=True)
            partial_path.write_text(
                json.dumps({"cases": results}, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            print(f"evaluated {index}/{len(cases)}", flush=True)

    report = {
        "checkpoint": "card6_part_a_step_1_current_guardrail_baseline",
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "guardrail_code_sha256": sha256(BACKEND / "retrieval/guardrail.py"),
        "model": model_metadata(),
        "sources": manifest,
        "protocol": {
            "guardrail_changed": False,
            "prompt_mutation": False,
            "harmbench_prompt_construction": "DirectRequest-compatible",
            "execution": "sequential",
            "temperature": 0,
            "wall_seconds_this_process": round(time.perf_counter() - started, 6),
        },
        "metrics": summarize(results),
        "cases": results,
    }
    args.report_json.parent.mkdir(parents=True, exist_ok=True)
    args.report_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.report_md.write_text(render_markdown(report), encoding="utf-8")
    partial_path.unlink(missing_ok=True)
    print(render_markdown(report), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BaselineError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
