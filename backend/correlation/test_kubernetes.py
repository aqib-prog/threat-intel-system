from __future__ import annotations

import gzip
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from correlation.kubernetes import KubernetesAuditAdapter
from correlation.local import LocalRawEvidenceStore
from correlation.models import ParseStatus, Platform


NOW = datetime(2026, 8, 11, 14, 0, tzinfo=timezone.utc)
AUDIT_ID = "e1a9b4c2-7d8e-4a3b-9c5d-1f2e3a4b5c6d"
OBJECT_UID = "77f3a812-bb2d-4340-a177-3e11b85848aa"
SECRET_MARKER = "MUST-NOT-ENTER-NORMALIZED-ATTRIBUTES"


def audit_event(*, stage: str = "ResponseComplete", audit_id: str = AUDIT_ID) -> dict:
    return {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "level": "RequestResponse",
        "auditID": audit_id,
        "stage": stage,
        "requestURI": "/api/v1/namespaces/production/secrets/db-root?pretty=true",
        "verb": "get",
        "user": {
            "username": "system:serviceaccount:default:reader",
            "uid": "service-account-uid",
            "groups": [
                "system:serviceaccounts",
                "system:serviceaccounts:default",
                "system:authenticated",
            ],
            "extra": {"credential.example/token": [SECRET_MARKER]},
        },
        "sourceIPs": ["198.51.100.72", "10.0.0.12"],
        "userAgent": "kubectl/v1.34.0 (linux/amd64)",
        "objectRef": {
            "resource": "secrets",
            "namespace": "production",
            "name": "db-root",
            "uid": OBJECT_UID,
            "apiVersion": "v1",
            "resourceVersion": "12345",
        },
        "responseStatus": {"status": "Success", "code": 200},
        "requestObject": {"kind": "Secret", "data": {"password": SECRET_MARKER}},
        "responseObject": {
            "kind": "Secret",
            "metadata": {"uid": OBJECT_UID},
            "data": {"password": SECRET_MARKER},
        },
        "requestReceivedTimestamp": "2026-08-11T13:59:58.100000Z",
        "stageTimestamp": "2026-08-11T13:59:58.120000Z",
        "annotations": {
            "authorization.k8s.io/decision": "allow",
            "authorization.k8s.io/reason": "RBAC: allowed by RoleBinding reader",
            "untrusted.example/secret": SECRET_MARKER,
        },
    }


class KubernetesAuditAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = LocalRawEvidenceStore(self.root / "evidence")
        self.adapter = KubernetesAuditAdapter(
            self.store,
            tenant_id="tenant-a",
            source_instance_id="audit-webhook-1",
            cluster_uid="cluster-production-uid",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _ingest(self, value: object):
        return self.adapter.ingest(
            json.dumps(value).encode(),
            media_type="application/json",
            collected_at=NOW,
        )

    def test_event_list_keeps_stages_separate_and_joins_by_audit_id(self) -> None:
        received = audit_event(stage="RequestReceived")
        received.pop("responseStatus")
        received.pop("responseObject")
        received["stageTimestamp"] = received["requestReceivedTimestamp"]
        events = self._ingest(
            {
                "kind": "EventList",
                "apiVersion": "audit.k8s.io/v1",
                "items": [received, audit_event()],
            }
        )
        self.assertEqual(len(events), 2)
        self.assertTrue(all(event.platform is Platform.KUBERNETES for event in events))
        self.assertTrue(all(event.parse_status is ParseStatus.PARSED for event in events))
        self.assertNotEqual(events[0].event_id, events[1].event_id)
        keys = [
            next(key for key in event.entity_keys if key.kind == "kubernetes_audit_id")
            for event in events
        ]
        self.assertEqual(keys[0], keys[1])
        self.assertEqual(events[0].native_event_id, AUDIT_ID)
        self.assertIsNone(events[0].native_sequence)

    def test_sensitive_bodies_user_extra_and_unknown_annotations_stay_raw(self) -> None:
        record = audit_event()
        payload = json.dumps(record).encode()
        event = self.adapter.ingest(
            payload, media_type="application/json", collected_at=NOW
        )[0]
        normalized = json.dumps(event.to_dict())
        self.assertEqual(event.parse_status, ParseStatus.PARSED)
        self.assertNotIn(SECRET_MARKER, normalized)
        self.assertNotIn("credential.example/token", normalized)
        self.assertNotIn("untrusted.example/secret", normalized)
        self.assertEqual(event.attributes["request"]["body_present"], True)
        self.assertEqual(event.attributes["response"]["body_present"], True)
        self.assertEqual(event.attributes["identity"]["extra_present_but_omitted"], True)
        self.assertEqual(event.attributes["evidence"]["other_annotations_omitted"], True)
        self.assertEqual(self.store.get(event.raw_evidence), payload)

    def test_source_ip_and_user_agent_trust_are_explicit(self) -> None:
        event = self._ingest(audit_event())[0]
        self.assertEqual(event.attributes["network"]["transport_peer"], "10.0.0.12")
        self.assertEqual(
            event.attributes["network"]["forwarded_source_ips_untrusted"],
            ("198.51.100.72",),
        )
        self.assertEqual(
            event.attributes["network"]["user_agent_untrusted"],
            "kubectl/v1.34.0 (linux/amd64)",
        )
        self.assertEqual(event.attributes["request"]["path"], "/api/v1/namespaces/production/secrets/db-root")
        self.assertEqual(event.attributes["request"]["query_present"], True)
        self.assertNotIn("pretty=true", json.dumps(event.to_dict()))

    def test_authenticated_and_impersonated_identities_are_distinct(self) -> None:
        record = audit_event()
        record["impersonatedUser"] = {
            "username": "alice@example.com",
            "uid": "impersonated-user-uid",
            "groups": ["developers"],
        }
        record["authenticationMetadata"] = {"impersonationConstraint": "impersonate"}
        event = self._ingest(record)[0]
        keys = {(key.kind, key.value, key.scope) for key in event.entity_keys}
        self.assertIn(
            (
                "kubernetes_user_name",
                "system:serviceaccount:default:reader",
                "cluster-production-uid",
            ),
            keys,
        )
        self.assertIn(
            (
                "kubernetes_impersonated_user_name",
                "alice@example.com",
                "cluster-production-uid",
            ),
            keys,
        )
        self.assertEqual(event.attributes["identity"]["impersonation_constraint"], "impersonate")

    def test_object_uid_falls_back_to_response_metadata_only(self) -> None:
        record = audit_event()
        record["objectRef"].pop("uid")
        event = self._ingest(record)[0]
        self.assertEqual(event.attributes["object"]["uid"], OBJECT_UID)
        self.assertEqual(event.attributes["object"]["uid_source"], "responseObject.metadata")
        self.assertIn(
            ("kubernetes_object_uid", OBJECT_UID, "cluster-production-uid"),
            {(key.kind, key.value, key.scope) for key in event.entity_keys},
        )

    def test_missing_ids_unknown_stage_and_bad_time_are_partial(self) -> None:
        record = audit_event()
        record.pop("auditID")
        record["stage"] = "FutureStage"
        record["stageTimestamp"] = "not-a-time"
        event = self._ingest(record)[0]
        self.assertEqual(event.parse_status, ParseStatus.PARTIAL)
        self.assertIsNone(event.native_event_id)
        self.assertNotIn("kubernetes_audit_id", {key.kind for key in event.entity_keys})
        self.assertTrue(any("auditID" in warning for warning in event.parse_warnings))
        self.assertTrue(any("stage" in warning for warning in event.parse_warnings))

    def test_payload_cannot_override_trusted_cluster_scope(self) -> None:
        record = audit_event()
        record["cluster_uid"] = "attacker-controlled-cluster"
        event = self._ingest(record)[0]
        self.assertEqual(event.attributes["cluster"]["uid"], "cluster-production-uid")
        self.assertTrue(all(key.scope == "cluster-production-uid" for key in event.entity_keys))

    def test_unknown_schema_and_non_audit_json_are_not_guessed(self) -> None:
        record = audit_event()
        record["apiVersion"] = "audit.k8s.io/v2"
        unknown = self._ingest(record)[0]
        self.assertEqual(unknown.parse_status, ParseStatus.UNPARSEABLE)
        self.assertEqual(unknown.attributes, {})
        ordinary = self._ingest({"kind": "Pod", "apiVersion": "v1"})[0]
        self.assertEqual(ordinary.parse_status, ParseStatus.UNPARSEABLE)

        wrapper = {
            "kind": "EventList",
            "apiVersion": "audit.k8s.io/v2",
            "items": [audit_event()],
        }
        wrapped = self._ingest(wrapper)[0]
        self.assertEqual(wrapped.parse_status, ParseStatus.UNPARSEABLE)
        self.assertIn("EventList version", wrapped.parse_warnings[0])

    def test_malformed_uri_uid_and_response_code_degrade_without_crashing(self) -> None:
        record = audit_event()
        record["requestURI"] = "http://[invalid"
        record["objectRef"]["uid"] = "x" * 1_025
        record["responseObject"].pop("metadata")
        record["responseStatus"]["code"] = 999
        event = self._ingest(record)[0]
        self.assertEqual(event.parse_status, ParseStatus.PARTIAL)
        self.assertIsNone(event.attributes["request"]["path"])
        self.assertIsNone(event.attributes["object"]["uid"])
        self.assertIsNone(event.attributes["response"]["code"])
        self.assertTrue(any("requestURI" in warning for warning in event.parse_warnings))
        self.assertTrue(any("objectRef.uid" in warning for warning in event.parse_warnings))
        self.assertTrue(any("HTTP status" in warning for warning in event.parse_warnings))

    def test_configuration_identifiers_are_normalized_once(self) -> None:
        adapter = KubernetesAuditAdapter(
            self.store,
            tenant_id=" tenant-a ",
            source_instance_id=" webhook-2 ",
            cluster_uid=" cluster-2 ",
        )
        event = adapter.ingest(
            json.dumps(audit_event()).encode(),
            media_type="application/json",
            collected_at=NOW,
        )[0]
        self.assertEqual(event.tenant_id, "tenant-a")
        self.assertEqual(event.source_instance_id, "webhook-2")
        self.assertTrue(all(key.scope == "cluster-2" for key in event.entity_keys))

    def test_bad_ndjson_line_is_isolated_with_precise_reason(self) -> None:
        duplicate = (
            '{"kind":"Event","apiVersion":"audit.k8s.io/v1",'
            '"auditID":"one","auditid":"two"}'
        )
        payload = duplicate + "\n" + json.dumps(audit_event()) + "\n"
        events = self.adapter.ingest(
            payload.encode(),
            media_type="application/x-ndjson",
            collected_at=NOW,
        )
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].parse_status, ParseStatus.UNPARSEABLE)
        self.assertIn("ambiguous", events[0].parse_warnings[0])
        self.assertEqual(events[1].parse_status, ParseStatus.PARSED)

    def test_gzip_event_limit_and_raw_evidence_ordering(self) -> None:
        compressed = gzip.compress(json.dumps(audit_event()).encode())
        event = self.adapter.ingest(
            compressed,
            media_type="application/octet-stream",
            collected_at=NOW,
        )[0]
        self.assertEqual(event.parse_status, ParseStatus.PARSED)
        self.assertEqual(self.store.get(event.raw_evidence), compressed)

        limited = KubernetesAuditAdapter(
            self.store,
            tenant_id="tenant-a",
            source_instance_id="limited-webhook",
            cluster_uid="cluster-production-uid",
            max_events_per_payload=1,
        )
        payload = json.dumps([audit_event(), audit_event()]).encode()
        limited_event = limited.ingest(
            payload, media_type="application/json", collected_at=NOW
        )[0]
        self.assertEqual(limited_event.parse_status, ParseStatus.UNPARSEABLE)
        self.assertIn("more than 1", limited_event.parse_warnings[0])
        self.assertEqual(self.store.get(limited_event.raw_evidence), payload)

        tiny = KubernetesAuditAdapter(
            self.store,
            tenant_id="tenant-a",
            source_instance_id="tiny-webhook",
            cluster_uid="cluster-production-uid",
            max_payload_bytes=4,
        )
        oversized = tiny.ingest(b"12345", media_type="text/plain", collected_at=NOW)[0]
        self.assertEqual(oversized.parse_status, ParseStatus.UNPARSEABLE)
        self.assertEqual(self.store.get(oversized.raw_evidence), b"12345")

    def test_deep_json_and_nonfinite_number_fail_safely(self) -> None:
        record = audit_event()
        nested: dict = {}
        record["requestObject"] = nested
        for _ in range(70):
            child: dict = {}
            nested["child"] = child
            nested = child
        deep = self._ingest(record)[0]
        self.assertEqual(deep.parse_status, ParseStatus.UNPARSEABLE)
        self.assertIn("depth limit", deep.parse_warnings[0])

        nonfinite = json.dumps(audit_event()).replace('"code": 200', '"code": NaN')
        bad = self.adapter.ingest(
            nonfinite.encode(), media_type="application/json", collected_at=NOW
        )[0]
        self.assertEqual(bad.parse_status, ParseStatus.UNPARSEABLE)
        self.assertIn("non-finite", bad.parse_warnings[0])


if __name__ == "__main__":
    unittest.main()
