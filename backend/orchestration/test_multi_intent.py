"""Unit tests for deterministic query splitting and multi-intent orchestration.

Three layers are covered, none of which need Neo4j or Ollama:

* ``query_splitter.segment_query`` - pure regex splitting (no DB by design).
* ``multi_intent._segment_disposition`` / ``_looks_like_word`` - the route/drop
  validity filter, exercised with ``driver=None`` so only the DB-free branches
  (cyber-signal regex, chit-chat/gibberish, question detection) run.
* ``multi_intent.run_multi_pipeline`` - the wrapper's branching and aggregation,
  with ``run_pipeline`` / ``get_driver`` / the log detector monkeypatched so the
  real pipeline never runs. This proves the single-intent path stays identical
  and that a multi-intent turn produces one independent segment per question.
"""

from __future__ import annotations

import os
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

# Keep these tests hermetic and deterministic: the LLM "and"-split augmentation
# is exercised separately (it needs a live model); here we assert the regex
# decomposition + routing, so force regex-only before importing.
os.environ.setdefault("MULTI_INTENT_LLM_SPLIT", "0")

from orchestration import multi_intent  # noqa: E402
from orchestration.multi_intent import (  # noqa: E402
    _looks_like_word,
    _segment_disposition,
    run_multi_pipeline,
)
from orchestration.pipeline import PipelineResult, Source, SuggestionAction  # noqa: E402
from orchestration.query_splitter import segment_query  # noqa: E402
from log_analysis.mixed_input import MixedLogInput  # noqa: E402
from log_analysis.detector import detect as detect_log  # noqa: E402
from retrieval.test_input_shape import EXACT_RAGAS_COMMAND  # noqa: E402


class SegmentQueryTests(unittest.TestCase):
    def test_blank_returns_empty(self):
        self.assertEqual(segment_query(""), [])
        self.assertEqual(segment_query("   \n  "), [])

    def test_single_question_one_candidate(self):
        self.assertEqual(
            segment_query("What techniques does APT29 use?"),
            ["What techniques does APT29 use?"],
        )

    def test_shell_continuation_is_not_a_line_boundary(self):
        self.assertEqual(
            segment_query("python tool.py \\\n  --mode full"),
            ["python tool.py \\\n  --mode full"],
        )

    def test_three_questions_split(self):
        out = segment_query(
            "What techniques does RIPTIDE use? "
            "Who ran the SolarWinds Compromise? "
            "List mitigations for T1055."
        )
        self.assertEqual(len(out), 3)
        self.assertIn("RIPTIDE", out[0])
        self.assertIn("SolarWinds", out[1])
        self.assertIn("T1055", out[2])

    def test_additive_adverb_is_a_boundary(self):
        out = segment_query("What is T1055? Also who uses it?")
        self.assertEqual(len(out), 2)
        # "Also" is both a boundary AND leading filler - it must be stripped.
        self.assertFalse(out[1].lower().startswith("also"))
        self.assertIn("who uses it", out[1])

    def test_additive_adverb_only_splits_before_a_clause_starter(self):
        # A genuine run-on second question (no terminator) opens with a clause
        # starter, so it still splits.
        self.assertEqual(
            segment_query("What is T1055 also who uses it"),
            ["What is T1055", "who uses it"],
        )
        self.assertEqual(
            segment_query("List techniques for APT29 additionally show mitigations"),
            ["List techniques for APT29", "show mitigations"],
        )

    def test_also_known_as_alias_is_never_split(self):
        # Regression: "also known as" is an alias marker inside ONE intent, not
        # a new question. "known" is not a clause starter, so no split. This is
        # the exact 156-case (S0002 / Mimikatz) the guard protects.
        self.assertEqual(
            segment_query("Which campaigns employ the use of Tool S0002, also known as Mimikatz?"),
            ["Which campaigns employ the use of Tool S0002, also known as Mimikatz?"],
        )
        # Same protection for the other alias phrasings.
        for q in (
            "Tell me about the tool also called PsExec",
            "Explain the group also referred to as Cozy Bear",
        ):
            self.assertEqual(segment_query(q), [q], q)

    def test_bare_and_or_never_splits_compound_entities(self):
        # These join one intent - splitting them would break entity extraction.
        self.assertEqual(
            segment_query("Compare APT29 and Lazarus Group techniques."),
            ["Compare APT29 and Lazarus Group techniques."],
        )
        self.assertEqual(
            segment_query("Show logon and network events for T1021."),
            ["Show logon and network events for T1021."],
        )

    def test_leading_filler_stripped(self):
        out = segment_query("Hey, so anyway, what is T1055?")
        self.assertEqual(out, ["what is T1055?"])

    def test_punctuation_only_residue_dropped(self):
        # "thanks!" is pure filler + punctuation -> no candidate survives.
        self.assertEqual(segment_query("thanks!"), [])

    def test_mixed_chitchat_and_question_kept_as_candidates(self):
        # segment_query does NOT drop chit-chat (that is the caller's job); it
        # only splits and cleans. "how are you?" survives as a candidate here.
        out = segment_query("hi how are you? What is T1055?")
        self.assertEqual(len(out), 2)
        self.assertIn("how are you", out[0].lower())
        self.assertIn("T1055", out[1])


class LooksLikeWordTests(unittest.TestCase):
    def test_real_words_pass(self):
        for word in ("hello", "techniques", "malware", "apt"):
            self.assertTrue(_looks_like_word(word), word)

    def test_gibberish_rejected(self):
        for junk in ("asdfghjkl", "qwrtplkjhg", "zxcvbnm", "x"):
            self.assertFalse(_looks_like_word(junk), junk)


class SegmentDispositionTests(unittest.TestCase):
    """driver=None exercises only the DB-free branches (no entity lookup)."""

    def test_empty_dropped(self):
        self.assertEqual(_segment_disposition("", None), "drop")
        self.assertEqual(_segment_disposition("   ", None), "drop")

    def test_gibberish_dropped(self):
        self.assertEqual(_segment_disposition("asdfghjkl", None), "drop")
        self.assertEqual(_segment_disposition("qwrtplkjhg zxcvbnm", None), "drop")

    def test_chitchat_dropped(self):
        self.assertEqual(_segment_disposition("how are you", None), "drop")
        self.assertEqual(_segment_disposition("good morning", None), "drop")

    def test_cyber_question_routed(self):
        self.assertEqual(
            _segment_disposition("What techniques does APT29 use?", None), "route"
        )

    def test_identifier_only_segment_is_not_mistaken_for_gibberish(self):
        self.assertEqual(_segment_disposition("T1055?", None), "route")

    def test_offtopic_question_still_routed(self):
        # A genuine off-topic question routes (guardrail soft-refuses) rather
        # than being silently dropped - the more transparent UX.
        self.assertEqual(
            _segment_disposition("what is the capital of France?", None), "route"
        )


def _result(query: str, **over) -> PipelineResult:
    """A faithful PipelineResult with per-query-distinct defaults."""
    base = dict(
        query=query,
        answer=f"ANSWER<{query}>",
        allowed=True,
        guardrail_category=None,
        filters={"q": [query]},
        sources=[Source(name=query, external_id=None, node_type="threat_actor", relevance_score=1.0)],
        retrieved_count=2,
        context_count=1,
        answer_source="rag",
        log_evidence=[],
    )
    base.update(over)
    return PipelineResult(**base)


class RunMultiPipelineTests(unittest.TestCase):
    def setUp(self):
        # No real graph driver and no real log detector in any wrapper test.
        self._patches = [
            mock.patch.object(multi_intent, "get_driver", return_value=None),
            mock.patch.object(
                multi_intent.log_analysis_detector,
                "detect",
                return_value=SimpleNamespace(is_raw_log=False),
            ),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    def test_blank_query_is_single_fallback(self):
        fake = mock.Mock(return_value=_result(""))
        with mock.patch.object(multi_intent, "run_pipeline", fake):
            out = run_multi_pipeline("")
        self.assertEqual(out.segments, [])
        fake.assert_called_once()

    def test_single_intent_is_identical_and_not_split(self):
        raw = "What techniques does APT29 use?"
        fake = mock.Mock(side_effect=lambda q, **k: _result(q))
        with mock.patch.object(multi_intent, "run_pipeline", fake):
            out = run_multi_pipeline(raw)
        self.assertEqual(out.segments, [])          # single-intent -> no cards
        self.assertEqual(out.answer, f"ANSWER<{raw}>")
        fake.assert_called_once()
        # Called with the RAW query, unchanged - the single path is untouched.
        self.assertEqual(fake.call_args.args[0], raw)

    def test_operational_command_is_kept_atomic(self):
        fake = mock.Mock(side_effect=lambda q, **k: _result(q, allowed=False))
        with mock.patch.object(multi_intent, "run_pipeline", fake), mock.patch.object(
            multi_intent, "decompose_query"
        ) as decomposer:
            out = run_multi_pipeline(EXACT_RAGAS_COMMAND)

        self.assertFalse(out.allowed)
        fake.assert_called_once_with(EXACT_RAGAS_COMMAND)
        decomposer.assert_not_called()

    def test_raw_log_paste_is_not_split(self):
        # A multi-line log has sentence-like punctuation, but the detector says
        # it is a raw log, so it must go to the single path intact.
        log = "process=powershell.exe. cmd=IEX. parent=winword.exe."
        fake = mock.Mock(side_effect=lambda q, **k: _result(q, answer="LOG"))
        with mock.patch.object(multi_intent, "run_pipeline", fake), mock.patch.object(
            multi_intent.log_analysis_detector,
            "detect",
            return_value=SimpleNamespace(is_raw_log=True),
        ):
            out = run_multi_pipeline(log)
        self.assertEqual(out.segments, [])
        fake.assert_called_once()
        self.assertEqual(fake.call_args.args[0], log)

    def test_standalone_fenced_log_is_unwrapped_for_structured_analysis(self):
        log = json.dumps(
            {
                "EventID": 1,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "ProviderName": "Microsoft-Windows-Sysmon",
                "UtcTime": "2026-07-29T10:00:00Z",
                "Image": "C:\\Windows\\System32\\whoami.exe",
                "CommandLine": "whoami.exe /all",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            },
            indent=2,
        )
        raw = f"```json\n{log}\n```"
        fake = mock.Mock(
            return_value=_result(
                log,
                answer="LOG",
                answer_source="log_analysis",
            )
        )
        with (
            mock.patch.object(
                multi_intent.log_analysis_detector,
                "detect",
                side_effect=detect_log,
            ),
            mock.patch.object(multi_intent, "run_pipeline", fake),
        ):
            out = run_multi_pipeline(raw)

        self.assertEqual(out.segments, [])
        self.assertEqual(out.query, raw)
        fake.assert_called_once_with(log)

    def test_mixed_log_and_one_question_produce_two_typed_segments(self):
        raw = '{"EventID":1}\nWhat techniques does APT29 use?'
        mixed = MixedLogInput(
            log_text='{"EventID":1}',
            request_text="What techniques does APT29 use?",
            platform="windows",
            request_position="after",
        )

        def fake(query, **_kwargs):
            if query == mixed.log_text:
                return _result(query, answer="LOG", answer_source="log_analysis")
            return _result(query)

        with (
            mock.patch.object(
                multi_intent.log_analysis_detector,
                "detect",
                return_value=SimpleNamespace(is_raw_log=True),
            ),
            mock.patch.object(multi_intent, "split_mixed_log_input", return_value=mixed),
            mock.patch.object(multi_intent, "run_pipeline", side_effect=fake),
        ):
            out = run_multi_pipeline(raw)

        self.assertEqual(len(out.segments), 2)
        self.assertEqual(out.segments[0].answer_source, "log_analysis")
        self.assertEqual(out.segments[0].display_title, "Log Analysis")
        self.assertEqual(out.segments[0].segment_kind, "log_analysis")
        self.assertEqual(out.segments[1].query, mixed.request_text)
        self.assertEqual(out.segments[1].segment_kind, "question")

    def test_mixed_log_and_multiple_questions_routes_each_independently(self):
        raw = '{"EventID":1}\nWhat is T1055? Who is APT29?'
        mixed = MixedLogInput(
            log_text='{"EventID":1}',
            request_text="What is T1055? Who is APT29?",
            platform="windows",
            request_position="after",
        )
        with (
            mock.patch.object(
                multi_intent.log_analysis_detector,
                "detect",
                return_value=SimpleNamespace(is_raw_log=True),
            ),
            mock.patch.object(multi_intent, "split_mixed_log_input", return_value=mixed),
            mock.patch.object(
                multi_intent,
                "run_pipeline",
                side_effect=lambda query, **_kwargs: _result(
                    query,
                    answer_source=(
                        "log_analysis" if query == mixed.log_text else "rag"
                    ),
                ),
            ) as fake,
        ):
            out = run_multi_pipeline(raw)

        self.assertEqual(len(out.segments), 3)
        self.assertEqual(
            [call.args[0] for call in fake.call_args_list],
            [mixed.log_text, "What is T1055?", "Who is APT29?"],
        )

    def test_questions_before_and_after_real_log_are_both_routed(self):
        log = json.dumps(
            {
                "EventID": 1,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "ProviderName": "Microsoft-Windows-Sysmon",
                "UtcTime": "2026-07-29T10:00:00Z",
                "Image": "C:\\Windows\\System32\\whoami.exe",
                "CommandLine": "whoami.exe /all",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            },
            indent=2,
        )
        raw = f"What is T1055?\n{log}\nWho is APT29?"

        def fake(query, **_kwargs):
            return _result(
                query,
                answer_source=("log_analysis" if query == log else "rag"),
            )

        with (
            mock.patch.object(
                multi_intent.log_analysis_detector,
                "detect",
                side_effect=detect_log,
            ),
            mock.patch.object(multi_intent, "run_pipeline", side_effect=fake) as run,
        ):
            out = run_multi_pipeline(raw)

        self.assertEqual(len(out.segments), 3)
        self.assertEqual(out.segments[0].display_title, "Log Analysis")
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [log, "What is T1055?", "Who is APT29?"],
        )

    def test_pure_analyze_log_directive_does_not_create_context_free_rag_card(self):
        raw = '{"EventID":1}\nPlease analyze this log.'
        mixed = MixedLogInput(
            log_text='{"EventID":1}',
            request_text="Please analyze this log.",
            platform="windows",
            request_position="after",
        )
        fake = mock.Mock(
            return_value=_result(
                mixed.log_text,
                answer="LOG",
                answer_source="log_analysis",
            )
        )
        with (
            mock.patch.object(
                multi_intent.log_analysis_detector,
                "detect",
                return_value=SimpleNamespace(is_raw_log=True),
            ),
            mock.patch.object(multi_intent, "split_mixed_log_input", return_value=mixed),
            mock.patch.object(multi_intent, "run_pipeline", fake),
        ):
            out = run_multi_pipeline(raw)

        self.assertEqual(out.segments, [])
        self.assertEqual(out.query, raw)
        fake.assert_called_once_with(mixed.log_text)

    def test_log_directive_is_dropped_when_independent_question_also_exists(self):
        raw = '{"EventID":1}\nAnalyze this log. What is T1055?'
        mixed = MixedLogInput(
            log_text='{"EventID":1}',
            request_text="Analyze this log. What is T1055?",
            platform="windows",
            request_position="after",
        )
        fake = mock.Mock(
            side_effect=lambda query, **_kwargs: _result(
                query,
                answer_source=(
                    "log_analysis" if query == mixed.log_text else "rag"
                ),
            )
        )
        with (
            mock.patch.object(
                multi_intent.log_analysis_detector,
                "detect",
                return_value=SimpleNamespace(is_raw_log=True),
            ),
            mock.patch.object(multi_intent, "split_mixed_log_input", return_value=mixed),
            mock.patch.object(multi_intent, "run_pipeline", fake),
        ):
            out = run_multi_pipeline(raw)

        self.assertEqual(len(out.segments), 2)
        self.assertEqual(
            [call.args[0] for call in fake.call_args_list],
            [mixed.log_text, "What is T1055?"],
        )

    def test_platform_qualified_log_directive_is_not_a_second_rag_card(self):
        raw = 'What is T1055?\nAnalyze this Windows Sysmon event:\n{"EventID":1}'
        mixed = MixedLogInput(
            log_text='{"EventID":1}',
            request_text="What is T1055?\nAnalyze this Windows Sysmon event",
            platform="windows",
            request_position="before",
        )
        fake = mock.Mock(
            side_effect=lambda query, **_kwargs: _result(
                query,
                answer_source=(
                    "log_analysis" if query == mixed.log_text else "rag"
                ),
            )
        )
        with (
            mock.patch.object(
                multi_intent.log_analysis_detector,
                "detect",
                return_value=SimpleNamespace(is_raw_log=True),
            ),
            mock.patch.object(
                multi_intent, "split_mixed_log_input", return_value=mixed
            ),
            mock.patch.object(
                multi_intent,
                "decompose_query",
                return_value=[
                    "What is T1055?",
                    "Analyze this Windows Sysmon event",
                ],
            ),
            mock.patch.object(multi_intent, "run_pipeline", fake),
        ):
            out = run_multi_pipeline(raw)

        self.assertEqual(len(out.segments), 2)
        self.assertEqual(
            [call.args[0] for call in fake.call_args_list],
            [mixed.log_text, "What is T1055?"],
        )

    def test_independent_sysmon_question_is_not_mistaken_for_log_directive(self):
        self.assertFalse(
            multi_intent._is_redundant_log_directive(
                "How does Windows Sysmon detect process creation?"
            )
        )
        self.assertTrue(
            multi_intent._is_redundant_log_directive(
                "Analyze this Windows Sysmon event:"
            )
        )

    def test_log_attribution_question_gets_evidence_limit_not_context_free_rag(self):
        raw = '{"EventID":1}\nDoes this log prove APT29 was responsible?'
        question = "Does this log prove APT29 was responsible?"
        mixed = MixedLogInput(
            log_text='{"EventID":1}',
            request_text=question,
            platform="windows",
            request_position="after",
        )
        fake = mock.Mock(
            return_value=_result(
                mixed.log_text,
                answer="LOG",
                answer_source="log_analysis",
            )
        )
        with (
            mock.patch.object(
                multi_intent.log_analysis_detector,
                "detect",
                return_value=SimpleNamespace(is_raw_log=True),
            ),
            mock.patch.object(multi_intent, "split_mixed_log_input", return_value=mixed),
            mock.patch.object(multi_intent, "run_pipeline", fake),
        ):
            out = run_multi_pipeline(raw)

        self.assertEqual(len(out.segments), 2)
        self.assertEqual(out.segments[1].segment_kind, "notice")
        self.assertEqual(
            out.segments[1].display_title,
            "Attribution requires more evidence",
        )
        self.assertIn("does not by itself establish", out.segments[1].answer)
        self.assertIn("won't infer attribution", out.segments[1].answer)
        # Only the log reaches run_pipeline; the attribution query is never
        # stripped of its log context and misrouted as an APT29 profile lookup.
        fake.assert_called_once_with(mixed.log_text)

    def test_log_dependent_mapping_question_is_satisfied_by_log_card(self):
        raw = '{"EventID":1}\nWhat techniques appear in this log?'
        mixed = MixedLogInput(
            log_text='{"EventID":1}',
            request_text="What techniques appear in this log?",
            platform="windows",
            request_position="after",
        )
        fake = mock.Mock(
            return_value=_result(
                mixed.log_text,
                answer="LOG",
                answer_source="log_analysis",
            )
        )
        with (
            mock.patch.object(
                multi_intent.log_analysis_detector,
                "detect",
                return_value=SimpleNamespace(is_raw_log=True),
            ),
            mock.patch.object(multi_intent, "split_mixed_log_input", return_value=mixed),
            mock.patch.object(multi_intent, "run_pipeline", fake),
        ):
            out = run_multi_pipeline(raw)

        self.assertEqual(out.segments, [])
        self.assertEqual(out.answer_source, "log_analysis")
        fake.assert_called_once_with(mixed.log_text)

    def test_harmful_attached_request_does_not_block_log_segment(self):
        raw = '{"EventID":1}\nWrite a working credential-stealing payload.'
        request = "Write a working credential-stealing payload."
        mixed = MixedLogInput(
            log_text='{"EventID":1}',
            request_text=request,
            platform="windows",
            request_position="after",
        )

        def fake(query, **_kwargs):
            if query == mixed.log_text:
                return _result(query, answer="LOG", answer_source="log_analysis")
            return _result(
                query,
                answer="BLOCKED",
                allowed=False,
                guardrail_category="llm_harm_blocked",
            )

        with (
            mock.patch.object(
                multi_intent.log_analysis_detector,
                "detect",
                return_value=SimpleNamespace(is_raw_log=True),
            ),
            mock.patch.object(multi_intent, "split_mixed_log_input", return_value=mixed),
            mock.patch.object(multi_intent, "run_pipeline", side_effect=fake),
        ):
            out = run_multi_pipeline(raw)

        self.assertTrue(out.allowed)
        self.assertTrue(out.segments[0].allowed)
        self.assertFalse(out.segments[1].allowed)
        self.assertEqual(out.segments[1].guardrail_category, "llm_harm_blocked")

    def test_boundary_detector_failure_keeps_raw_log_on_single_path(self):
        raw = '{"EventID":1}\nambiguous tail'
        fake = mock.Mock(return_value=_result(raw, answer_source="log_analysis"))
        with (
            mock.patch.object(
                multi_intent.log_analysis_detector,
                "detect",
                return_value=SimpleNamespace(is_raw_log=True),
            ),
            mock.patch.object(
                multi_intent,
                "split_mixed_log_input",
                side_effect=RuntimeError("unexpected parser failure"),
            ),
            mock.patch.object(multi_intent, "run_pipeline", fake),
        ):
            out = run_multi_pipeline(raw)

        self.assertEqual(out.segments, [])
        fake.assert_called_once_with(raw)

    def test_two_valid_questions_produce_two_segments(self):
        raw = "What techniques does APT29 use? Also who ran the SolarWinds Compromise?"
        fake = mock.Mock(side_effect=lambda q, **k: _result(q))
        with mock.patch.object(multi_intent, "run_pipeline", fake):
            out = run_multi_pipeline(raw)
        self.assertEqual(len(out.segments), 2)
        self.assertIn("APT29", out.segments[0].query)
        self.assertIn("SolarWinds", out.segments[1].query)
        # Each segment carries its OWN answer, in order.
        self.assertEqual(out.segments[0].answer, f"ANSWER<{out.segments[0].query}>")
        self.assertEqual(out.segments[1].answer, f"ANSWER<{out.segments[1].query}>")
        # Top-level answer is the joined aggregate; counts are summed.
        self.assertIn(out.segments[0].answer, out.answer)
        self.assertIn(out.segments[1].answer, out.answer)
        self.assertEqual(out.retrieved_count, 4)  # 2 + 2

    def test_one_valid_plus_chitchat_runs_only_the_valid_candidate(self):
        # Once decomposition has positively separated multiple candidates,
        # discarded filler must not be reattached to the guardrail input.
        raw = "hi how are you? What is T1055?"
        fake = mock.Mock(side_effect=lambda q, **k: _result(q))
        with mock.patch.object(multi_intent, "run_pipeline", fake):
            out = run_multi_pipeline(raw)
        self.assertEqual(out.segments, [])
        fake.assert_called_once()
        self.assertEqual(fake.call_args.args[0], "What is T1055?")

    def test_one_valid_plus_gibberish_runs_only_the_valid_candidate(self):
        raw = "What techniques does Axiom use? asdfghjkl qwrtplkjhg."
        fake = mock.Mock(side_effect=lambda q, **k: _result(q))
        with mock.patch.object(multi_intent, "run_pipeline", fake):
            out = run_multi_pipeline(raw)
        self.assertEqual(out.segments, [])
        fake.assert_called_once_with("What techniques does Axiom use?")

    def test_all_chitchat_falls_back_to_single(self):
        raw = "hi how are you? thanks so much!"
        fake = mock.Mock(side_effect=lambda q, **k: _result(q))
        with mock.patch.object(multi_intent, "run_pipeline", fake):
            out = run_multi_pipeline(raw)
        self.assertEqual(out.segments, [])
        fake.assert_called_once()

    def test_aggregate_sources_deduped_and_filters_merged(self):
        raw = "What does APT29 use? Also what does FIN7 use?"
        shared = Source(name="Mimikatz", external_id="S0002", node_type="tool", relevance_score=5.0)

        def fake(q, **k):
            uniq = Source(name=q, external_id=None, node_type="threat_actor", relevance_score=1.0)
            return _result(q, sources=[shared, uniq], filters={"actor": [q]})

        with mock.patch.object(multi_intent, "run_pipeline", mock.Mock(side_effect=fake)):
            out = run_multi_pipeline(raw)
        self.assertEqual(len(out.segments), 2)
        # Shared Mimikatz appears once; each unique actor source is kept.
        names = [s.name for s in out.sources]
        self.assertEqual(names.count("Mimikatz"), 1)
        self.assertEqual(len(out.sources), 3)  # 1 shared + 2 unique
        # Filters merged across segments under the same key.
        self.assertEqual(len(out.filters["actor"]), 2)

    def test_same_named_sources_with_different_ids_are_not_collapsed(self):
        raw = "What is T1087.004? Also what is T1136.003?"
        first = Source(
            name="Cloud Account",
            external_id="T1087.004",
            node_type="Technique",
            relevance_score=5.0,
        )
        second = Source(
            name="Cloud Account",
            external_id="T1136.003",
            node_type="Technique",
            relevance_score=5.0,
        )

        def fake(query, **_kwargs):
            source = first if "T1087.004" in query else second
            return _result(query, sources=[source])

        with mock.patch.object(
            multi_intent, "run_pipeline", mock.Mock(side_effect=fake)
        ):
            out = run_multi_pipeline(raw)
        self.assertEqual(
            {source.external_id for source in out.sources},
            {"T1087.004", "T1136.003"},
        )

    def test_segment_suggestion_actions_are_preserved_and_aggregated(self):
        raw = "What is APT20? Also what is T10557?"

        def fake(query, **_kwargs):
            original = "APT20" if "APT20" in query else "T10557"
            replacement = "APT2" if original == "APT20" else "T1055"
            action = SuggestionAction(
                label=replacement,
                query=query.replace(original, replacement),
                original=original,
            )
            return _result(
                query,
                suggestions=[action.label],
                suggestion_actions=[action],
            )

        with mock.patch.object(
            multi_intent, "run_pipeline", mock.Mock(side_effect=fake)
        ):
            out = run_multi_pipeline(raw)

        self.assertEqual(len(out.segments), 2)
        self.assertEqual(
            [action.original for action in out.suggestion_actions],
            ["APT20", "T10557"],
        )
        self.assertEqual(
            [segment.suggestion_actions[0].original for segment in out.segments],
            ["APT20", "T10557"],
        )


if __name__ == "__main__":
    unittest.main()
