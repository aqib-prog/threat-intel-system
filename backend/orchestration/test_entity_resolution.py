"""Hermetic regressions for mixed actor codes and suggestion click targets."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from orchestration import pipeline  # noqa: E402


class _Result:
    def __init__(self, value):
        self.value = value

    def single(self):
        return self.value


class _Session:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def run(self, query, **_parameters):
        if "collect(DISTINCT nm) AS names" in query:
            return _Result({"names": ["APT2", "APT28", "APT29", "APT42"]})
        return _Result({"items": []})


class _Driver:
    def session(self):
        return _Session()

    def close(self):
        return None


class MixedActorResolutionTests(unittest.TestCase):
    def test_digit_lookalike_actor_code_is_captured_as_one_unresolved_code(self):
        for query, expected in (
            ("What techniques does APT2O use?", {"apt2o"}),
            ("What software does FIN7I use?", {"fin7i"}),
            ("Tell me about UNC24L2", {"unc24l2"}),
        ):
            with self.subTest(query=query):
                self.assertEqual(pipeline.actor_codes_in_query(query), expected)
        self.assertEqual(
            pipeline.without_actor_codes(
                "What techniques does APT2O use?",
                {"apt2o"},
            ),
            "What techniques does use?",
        )

    def test_unresolved_code_is_removed_without_damaging_valid_code(self):
        self.assertEqual(
            pipeline.without_actor_codes(
                "What techniques do APT29 and APT20 use?", {"apt20"}
            ),
            "What techniques do APT29 use?",
        )
        self.assertEqual(
            pipeline.without_actor_codes(
                "Tell me about APT20 and APT29", {"apt20"}
            ),
            "Tell me about APT29",
        )
        self.assertEqual(
            pipeline.without_actor_codes(
                "What techniques do APT29, APT20, and APT28 use?", {"apt20"}
            ),
            "What techniques do APT29 and APT28 use?",
        )

    def test_comparison_and_intersection_require_every_actor(self):
        for query in (
            "Compare APT29 and APT20 techniques",
            "Which techniques do APT29 and APT20 both use?",
            "List techniques shared by APT29 and APT20",
            "Differences between APT29 and APT20",
        ):
            with self.subTest(query=query):
                self.assertTrue(pipeline.requires_all_actor_references(query))
        self.assertFalse(
            pipeline.requires_all_actor_references(
                "What techniques do APT29 and APT20 use?"
            )
        )
        self.assertEqual(
            pipeline.without_actor_codes(
                "What techniques do APT20 and APT29 use?", {"apt20"}
            ),
            "What techniques do APT29 use?",
        )

    def test_suggestion_action_replaces_the_invalid_code_not_the_first_code(self):
        query = "Compare APT29 and APT20 techniques"
        actions = pipeline.reference_suggestion_actions(
            _Driver(), query, target_actor_codes={"apt20"}
        )
        apt2 = next(action for action in actions if action.label == "APT2")
        self.assertEqual(apt2.original, "APT20")
        self.assertEqual(apt2.query, "Compare APT29 and APT2 techniques")
        self.assertIn("APT29", apt2.query)
        self.assertNotIn("APT29", [action.label for action in actions])

    def test_name_typo_action_preserves_relationship_intent(self):
        query = "What techniques does Lazrus Group use?"
        with mock.patch.object(
            pipeline,
            "_entity_name_index",
            return_value=[("Lazarus Group", "G0032")],
        ):
            actions = pipeline.reference_suggestion_actions(_Driver(), query)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].label, "Lazarus Group (G0032)")
        self.assertEqual(
            actions[0].query, "What techniques does Lazarus Group use?"
        )

    def test_structured_codes_are_not_fuzzed_as_entity_names(self):
        query = "What techniques do APT29 and APT20 use?"
        with mock.patch.object(
            pipeline,
            "_entity_name_index",
            return_value=[("Linux and Mac Permissions", "T1222.002")],
        ):
            actions = pipeline.reference_suggestion_actions(
                _Driver(), query, target_actor_codes={"apt20"}
            )
        self.assertNotIn(
            "Linux and Mac Permissions (T1222.002)",
            [action.label for action in actions],
        )

    def test_name_typo_can_coexist_with_a_structured_actor_code(self):
        query = "What techniques do APT29 and Lazrus Group use?"
        with mock.patch.object(
            pipeline,
            "_entity_name_index",
            return_value=[("Lazarus Group", "G0032")],
        ):
            actions = pipeline.reference_suggestion_actions(_Driver(), query)
        lazarus = next(
            action for action in actions if action.label == "Lazarus Group (G0032)"
        )
        self.assertEqual(
            lazarus.query, "What techniques do APT29 and Lazarus Group use?"
        )

    def test_multiple_unknown_codes_each_receive_a_targeted_action(self):
        query = "What techniques do APT20 and APT21 use?"
        actions = pipeline.reference_suggestion_actions(
            _Driver(),
            query,
            target_actor_codes={"apt20", "apt21"},
        )
        self.assertEqual({action.original for action in actions}, {"APT20", "APT21"})
        for action in actions:
            other = "APT21" if action.original == "APT20" else "APT20"
            self.assertIn(other, action.query)

    def test_pipeline_stops_comparison_when_one_actor_is_unresolved(self):
        query = "Compare APT29 and APT20 techniques"
        action = pipeline.SuggestionAction(
            label="APT2",
            query="Compare APT29 and APT2 techniques",
            original="APT20",
        )
        with (
            mock.patch.object(
                pipeline.log_analysis_detector,
                "detect",
                return_value=SimpleNamespace(is_raw_log=False),
            ),
            mock.patch.object(pipeline, "guardrail", return_value={"allowed": True}),
            mock.patch.object(pipeline, "is_low_signal_query", return_value=False),
            mock.patch.object(pipeline, "get_driver", return_value=_Driver()),
            mock.patch.object(pipeline, "explicit_ids_exist", return_value=True),
            mock.patch.object(
                pipeline, "resolve_actor_codes", return_value={"apt29"}
            ),
            mock.patch.object(
                pipeline, "reference_suggestion_actions", return_value=[action]
            ),
            mock.patch.object(pipeline, "extract_filters") as extract_filters,
        ):
            result = pipeline.run_pipeline(query)

        self.assertIn("can't answer this comparison reliably", result.answer)
        self.assertEqual(result.suggestion_actions, [action])
        extract_filters.assert_not_called()

    def test_pipeline_uses_only_recognized_actor_for_union_query(self):
        query = "What techniques do APT29 and APT20 use?"
        with (
            mock.patch.object(
                pipeline.log_analysis_detector,
                "detect",
                return_value=SimpleNamespace(is_raw_log=False),
            ),
            mock.patch.object(pipeline, "guardrail", return_value={"allowed": True}),
            mock.patch.object(pipeline, "is_low_signal_query", return_value=False),
            mock.patch.object(pipeline, "get_driver", return_value=_Driver()),
            mock.patch.object(pipeline, "explicit_ids_exist", return_value=True),
            mock.patch.object(
                pipeline, "resolve_actor_codes", return_value={"apt29"}
            ),
            mock.patch.object(
                pipeline, "reference_suggestion_actions", return_value=[]
            ),
            mock.patch.object(
                pipeline, "extract_filters", return_value={}
            ) as extract_filters,
            mock.patch.object(pipeline, "is_ambiguous_short_reference", return_value=False),
            mock.patch.object(pipeline, "has_unresolved_explicit_id", return_value=False),
            mock.patch.object(pipeline, "fetch_telemetry_seed_nodes", return_value=[]),
            mock.patch.object(pipeline, "fetch_filter_seed_nodes", return_value=[]),
            mock.patch.object(pipeline, "search", return_value=[]),
        ):
            pipeline.run_pipeline(query)

        extract_filters.assert_called_once_with(
            "What techniques do APT29 use?", mock.ANY
        )


if __name__ == "__main__":
    unittest.main()
