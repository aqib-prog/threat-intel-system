from __future__ import annotations

import unittest
from dataclasses import replace

from correlation.ground_truth import (
    ComponentKind,
    EventJoinMethod,
    GroundTruthCoverageError,
    GroundTruthManifest,
    LabelMethod,
    TruthComponent,
    evaluate_components,
)
from correlation.models import EntityKey
from correlation.test_heuristics import _event
from correlation.test_shadow import _artifacts


def _with_activity(event, activity_id: str):
    return replace(
        event,
        entity_keys=(
            *event.entity_keys,
            EntityKey("activity_id", activity_id, "host:boot"),
        ),
    )


def _component(key: str, *event_ids: str, kind=ComponentKind.ATTACK):
    return TruthComponent(
        component_key=key,
        tenant_id="tenant-a",
        event_refs=tuple(sorted(("tenant-a", event_id) for event_id in event_ids)),
        kind=kind,
        run_id="run-1",
        step_ids=("step-1",),
        technique_ids=("T1059.001",),
    )


def _manifest(components, **overrides):
    values = {
        "source_name": "capture-fixture",
        "source_uri": "https://example.test/capture.json",
        "source_sha256": "a" * 64,
        "license_name": "CC-BY-4.0",
        "label_method": LabelMethod.CAPTURE_ORCHESTRATOR,
        "event_join_method": EventJoinMethod.NATIVE_EVENT_ID,
        "benign_background_included": True,
        "exhaustive_event_assignment": True,
        "components": components,
    }
    values.update(overrides)
    return GroundTruthManifest.create(**values)


class GroundTruthEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            _with_activity(_event("parent", pid="100"), "activity-parent"),
            _with_activity(
                _event("child", pid="200", ppid="100", seconds=1),
                "activity-child",
            ),
        ]
        self.snapshot, self.heuristic_edges = _artifacts(self.events)
        from correlation.shadow import ShadowComparator

        self.shadow = ShadowComparator().compare(
            self.snapshot,
            self.heuristic_edges,
        )

    def test_shadow_closes_a_true_undermerge_exactly(self):
        manifest = _manifest([_component("expected-chain", "parent", "child")])

        result = evaluate_components(manifest, self.snapshot, self.shadow)

        self.assertTrue(result.promotion_evidence_qualified)
        self.assertEqual(result.baseline.false_negative_pairs, 1)
        self.assertEqual(result.baseline.recall, 0.0)
        self.assertEqual(result.shadow.true_positive_pairs, 1)
        self.assertEqual(result.shadow.false_positive_pairs, 0)
        self.assertEqual(result.shadow.precision, 1.0)
        self.assertEqual(result.shadow.recall, 1.0)
        self.assertEqual(result.f1_delta, 1.0)

    def test_shadow_overmerge_is_counted_as_false_positive(self):
        manifest = _manifest(
            [
                _component("expected-parent", "parent"),
                _component(
                    "expected-child",
                    "child",
                    kind=ComponentKind.BENIGN,
                ),
            ]
        )

        result = evaluate_components(manifest, self.snapshot, self.shadow)

        self.assertEqual(result.baseline.false_positive_pairs, 0)
        self.assertEqual(result.baseline.precision, 1.0)
        self.assertEqual(result.shadow.false_positive_pairs, 1)
        self.assertEqual(result.shadow.precision, 0.0)
        self.assertEqual(result.shadow.true_negative_pairs, 0)

    def test_only_independent_capture_labels_qualify_for_promotion(self):
        components = [_component("one", "parent", "child")]

        posthoc = _manifest(
            components,
            label_method=LabelMethod.POSTHOC_ANALYST,
        )
        window_joined = _manifest(
            components,
            event_join_method=EventJoinMethod.TIME_WINDOW,
        )
        no_benign = _manifest(
            components,
            benign_background_included=False,
        )

        self.assertFalse(posthoc.promotion_evidence_qualified)
        self.assertFalse(window_joined.promotion_evidence_qualified)
        self.assertFalse(no_benign.promotion_evidence_qualified)

    def test_manifest_round_trip_and_tamper_detection(self):
        manifest = _manifest([_component("one", "parent", "child")])

        self.assertEqual(
            GroundTruthManifest.from_dict(manifest.to_dict()),
            manifest,
        )
        payload = manifest.to_dict()
        payload["source_name"] = "tampered"
        with self.assertRaises(ValueError):
            GroundTruthManifest.from_dict(payload)

    def test_non_exhaustive_or_mismatched_event_sets_cannot_be_scored(self):
        non_exhaustive = _manifest(
            [_component("one", "parent")],
            exhaustive_event_assignment=False,
        )
        mismatched = _manifest([_component("one", "parent")])

        with self.assertRaises(GroundTruthCoverageError):
            evaluate_components(non_exhaustive, self.snapshot, self.shadow)
        with self.assertRaises(GroundTruthCoverageError):
            evaluate_components(mismatched, self.snapshot, self.shadow)

    def test_duplicate_assignments_and_invalid_techniques_are_rejected(self):
        duplicate = _component("duplicate", "parent")
        with self.assertRaises(ValueError):
            _manifest([_component("one", "parent"), duplicate])
        with self.assertRaises(ValueError):
            TruthComponent(
                component_key="bad",
                tenant_id="tenant-a",
                event_refs=(("tenant-a", "parent"),),
                kind=ComponentKind.ATTACK,
                run_id="run-1",
                technique_ids=("not-a-technique",),
            )


if __name__ == "__main__":
    unittest.main()
