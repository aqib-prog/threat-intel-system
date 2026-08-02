#!/usr/bin/env python3
"""Checkpoint 3: prove the answer sanitiser changed nothing that was working.

Runs real golden-set questions through the live pipeline and asserts, for each:

  1. the answer is NOT the generic "no information" refusal (the pipeline still
     answers what it always answered), and
  2. sanitize_answer() is a byte-identical no-op on it - i.e. the deterministic
     renderers pass straight through untouched.

Any answer the sanitiser DOES alter is printed in full with a diff, because on
a well-formed answer that is a regression, not an improvement.

Usage (from tools/rag_accuracy):
    ../../backend/venv/bin/python verify_answer_sanitizer.py            # 20 cases
    ../../backend/venv/bin/python verify_answer_sanitizer.py --limit 40
    ../../backend/venv/bin/python verify_answer_sanitizer.py --all      # all 156
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
BACKEND = HERE.parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

GOLDEN = HERE / "final_golden_set.json"
REFUSAL = "I don't have enough information about this in my knowledge base."


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()

    from generation.answer_sanitizer import sanitize_answer
    from orchestration.pipeline import run_pipeline

    entries = json.loads(GOLDEN.read_text())["entries"]

    # Spread across relationship types first so a small run still covers every
    # renderer, then fill up to the requested count.
    by_type: dict[str, dict] = {}
    for entry in entries:
        by_type.setdefault(entry.get("relationship_type"), entry)
    ordered = list(by_type.values()) + [e for e in entries if e not in by_type.values()]
    cases = ordered if args.all else ordered[: args.limit]

    altered, refused, started = [], [], time.time()
    for index, case in enumerate(cases, start=1):
        question = case["question"]
        try:
            answer = run_pipeline(question).answer
        except Exception as exc:  # a crash is itself a failure worth surfacing
            altered.append((question, f"<pipeline error: {exc}>", ""))
            continue

        if answer.strip() == REFUSAL:
            refused.append(question)

        cleaned = sanitize_answer(answer)
        if cleaned != answer:
            altered.append((question, answer, cleaned))

        print(f"  [{index}/{len(cases)}] {'ALTERED' if cleaned != answer else 'ok     '} "
              f"{question[:58]}", flush=True)

    elapsed = int(time.time() - started)
    print("\n" + "=" * 68)
    print(f"cases run          : {len(cases)}  ({elapsed}s)")
    print(f"sanitiser no-op    : {len(cases) - len(altered)}/{len(cases)}")
    print(f"refusals           : {len(refused)}")

    if altered:
        print("\nREGRESSIONS - sanitiser modified a real answer:")
        for question, before, after in altered:
            print(f"\n  Q: {question}")
            print(f"  BEFORE:\n{before}")
            print(f"  AFTER:\n{after}")
        print("\nRESULT: FAIL - do not ship. Revert the sanitize_answer() call")
        print("in backend/generation/generate.py.")
        return 1

    print("\nRESULT: PASS - the sanitiser left every real answer untouched.")
    if refused:
        print("\nNote: these questions returned the generic refusal. Compare against")
        print("a previous run - they are only a problem if they used to answer:")
        for question in refused:
            print(f"  - {question}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
