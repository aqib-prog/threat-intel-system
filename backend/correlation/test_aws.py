from __future__ import annotations

import gzip
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from correlation.aws import CloudTrailAdapter, CloudTrailIntegrityStatus
from correlation.local import LocalRawEvidenceStore
from correlation.models import ParseStatus, Platform


NOW = datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc)


def cloudtrail_event(
    *,
    event_id: str = "11111111-2222-3333-4444-555555555555",
    request_id: str = "request-123",
    recipient_account: str = "123456789012",
) -> dict:
    return {
        "eventVersion": "1.09",
        "userIdentity": {
            "type": "AssumedRole",
            "principalId": "AROATEST:analyst-session",
            "arn": "arn:aws:sts::123456789012:assumed-role/Analyst/analyst-session",
            "accountId": "123456789012",
            "accessKeyId": "ASIATESTACCESSKEY",
            "userName": "analyst-session",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": "AROATEST",
                    "arn": "arn:aws:iam::123456789012:role/Analyst",
                    "accountId": "123456789012",
                    "userName": "Analyst",
                },
                "attributes": {
                    "creationDate": "2026-08-11T11:30:00Z",
                    "mfaAuthenticated": "true",
                },
                "sourceIdentity": "security-team",
                "signInSessionArn": (
                    "arn:aws:signin:us-east-1:123456789012:session/session-uuid"
                ),
            },
        },
        "eventTime": "2026-08-11T11:59:00Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.25",
        "userAgent": "aws-cli/2.17",
        "requestParameters": {
            "bucketName": "sensitive-bucket",
            "sessionToken": "MUST-NOT-ENTER-NORMALIZED-ATTRIBUTES",
        },
        "responseElements": {
            "credentials": {
                "secretAccessKey": "MUST-NOT-ENTER-NORMALIZED-ATTRIBUTES"
            }
        },
        "requestID": request_id,
        "eventID": event_id,
        "readOnly": True,
        "eventType": "AwsApiCall",
        "managementEvent": False,
        "recipientAccountId": recipient_account,
        "eventCategory": "Data",
        "resources": [
            {
                "ARN": "arn:aws:s3:::sensitive-bucket/private.txt",
                "accountId": recipient_account,
                "type": "AWS::S3::Object",
            }
        ],
        "tlsDetails": {
            "tlsVersion": "TLSv1.3",
            "cipherSuite": "TLS_AES_128_GCM_SHA256",
            "clientProvidedHostHeader": "s3.amazonaws.com",
        },
    }


class CloudTrailAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = LocalRawEvidenceStore(self.root / "evidence")
        self.adapter = CloudTrailAdapter(
            self.store,
            tenant_id="tenant-a",
            source_instance_id="organization-trail",
            allowed_recipient_account_ids=("123456789012", "210987654321"),
            allowed_regions=("us-east-1",),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _ingest(self, value: object):
        return self.adapter.ingest(
            json.dumps(value).encode(),
            media_type="application/json",
            collected_at=NOW,
        )

    def test_gzip_records_wrapper_is_bounded_and_raw_bytes_are_preserved(self) -> None:
        first = cloudtrail_event()
        second = cloudtrail_event(
            event_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            request_id="request-456",
        )
        compressed = gzip.compress(json.dumps({"Records": [first, second]}).encode())
        events = self.adapter.ingest(
            compressed,
            media_type="application/gzip",
            content_encoding="gzip",
            collected_at=NOW,
        )
        self.assertEqual(len(events), 2)
        self.assertTrue(all(event.platform is Platform.AWS for event in events))
        self.assertTrue(all(event.parse_status is ParseStatus.PARSED for event in events))
        self.assertEqual(self.store.get(events[0].raw_evidence), compressed)
        self.assertEqual(events[1].native_event_id, second["eventID"])

    def test_identity_request_and_resource_keys_have_distinct_scopes(self) -> None:
        event = self._ingest(cloudtrail_event())[0]
        keys = {(key.kind, key.value, key.scope) for key in event.entity_keys}
        self.assertIn(
            (
                "cloudtrail_event_id",
                "11111111-2222-3333-4444-555555555555",
                "aws",
            ),
            keys,
        )
        self.assertIn(
            (
                "cloud_request_id",
                "request-123",
                "aws:123456789012:us-east-1:s3.amazonaws.com",
            ),
            keys,
        )
        self.assertIn(
            ("aws_access_key_id", "ASIATESTACCESSKEY", "aws:123456789012"),
            keys,
        )
        self.assertIn(
            (
                "aws_resource_arn",
                "arn:aws:s3:::sensitive-bucket/private.txt",
                "aws",
            ),
            keys,
        )

    def test_request_and_response_secrets_never_enter_normalized_attributes(self) -> None:
        event = self._ingest(cloudtrail_event())[0]
        serialized = json.dumps(event.to_dict())
        self.assertNotIn("MUST-NOT-ENTER-NORMALIZED-ATTRIBUTES", serialized)
        self.assertNotIn("requestParameters", serialized)
        self.assertNotIn("responseElements", serialized)
        self.assertEqual(
            self.store.get(event.raw_evidence), json.dumps(cloudtrail_event()).encode()
        )

    def test_shared_event_id_links_cross_account_copies_without_merging_event_ids(self) -> None:
        left = cloudtrail_event(recipient_account="123456789012")
        right = cloudtrail_event(
            event_id="99999999-8888-7777-6666-555555555555",
            recipient_account="210987654321",
        )
        shared_event_id = "12345678-90ab-cdef-1234-567890abcdef"
        left["sharedEventID"] = shared_event_id
        right["sharedEventID"] = shared_event_id
        events = self._ingest({"Records": [left, right]})
        shared = [
            next(key for key in event.entity_keys if key.kind == "cloudtrail_shared_event_id")
            for event in events
        ]
        native_ids = {event.native_event_id for event in events}
        self.assertEqual(shared[0], shared[1])
        self.assertEqual(len(native_ids), 2)

    def test_duplicate_delivery_keeps_evidence_occurrences_but_reuses_native_key(self) -> None:
        record = cloudtrail_event()
        standalone = self._ingest(record)[0]
        wrapped = self._ingest({"Records": [record]})[0]
        standalone_key = next(
            key for key in standalone.entity_keys if key.kind == "cloudtrail_event_id"
        )
        wrapped_key = next(
            key for key in wrapped.entity_keys if key.kind == "cloudtrail_event_id"
        )
        self.assertEqual(standalone_key, wrapped_key)
        self.assertNotEqual(standalone.raw_evidence.sha256, wrapped.raw_evidence.sha256)
        self.assertNotEqual(standalone.event_id, wrapped.event_id)

    def test_addendum_links_to_original_event_and_request(self) -> None:
        record = cloudtrail_event()
        record["addendum"] = {
            "reason": "UPDATED_DATA",
            "updatedFields": "responseElements",
            "originalEventID": "fedcba98-7654-3210-fedc-ba9876543210",
            "originalRequestID": "original-request-id",
        }
        event = self._ingest(record)[0]
        keys = {(key.kind, key.value) for key in event.entity_keys}
        self.assertIn(
            (
                "cloudtrail_original_event_id",
                "fedcba98-7654-3210-fedc-ba9876543210",
            ),
            keys,
        )
        self.assertIn(("cloud_original_request_id", "original-request-id"), keys)

    def test_unknown_major_version_is_preserved_but_not_guessed(self) -> None:
        record = cloudtrail_event()
        record["eventVersion"] = "2.00"
        event = self._ingest(record)[0]
        self.assertEqual(event.parse_status, ParseStatus.UNPARSEABLE)
        self.assertEqual(event.attributes, {})
        self.assertIn("unsupported", event.parse_warnings[0])

    def test_missing_event_id_and_source_allowlist_mismatch_are_partial(self) -> None:
        record = cloudtrail_event()
        del record["eventID"]
        record["recipientAccountId"] = "999999999999"
        record["awsRegion"] = "eu-west-1"
        event = self._ingest(record)[0]
        self.assertEqual(event.parse_status, ParseStatus.PARTIAL)
        self.assertTrue(any("eventID" in warning for warning in event.parse_warnings))
        self.assertEqual(
            sum("allowlist" in warning for warning in event.parse_warnings), 2
        )

    def test_integrity_claim_is_trusted_configuration_not_payload_data(self) -> None:
        record = cloudtrail_event()
        record["integrity_status"] = "aws_digest_validated"
        event = self._ingest(record)[0]
        self.assertEqual(event.attributes["evidence"]["integrity_status"], "unverified")

        validated = CloudTrailAdapter(
            self.store,
            tenant_id="tenant-a",
            source_instance_id="validated-trail",
            integrity_status=CloudTrailIntegrityStatus.AWS_DIGEST_VALIDATED,
            integrity_proof_uri="s3://audit/proofs/validation-report.json",
        )
        validated_event = validated.ingest(
            json.dumps(record).encode(),
            media_type="application/json",
            collected_at=NOW,
        )[0]
        self.assertEqual(
            validated_event.attributes["evidence"]["integrity_status"],
            "aws_digest_validated",
        )
        self.assertRaises(
            ValueError,
            CloudTrailAdapter,
            self.store,
            tenant_id="tenant-a",
            source_instance_id="bad-config",
            integrity_status=CloudTrailIntegrityStatus.AWS_DIGEST_VALIDATED,
        )
        self.assertRaises(
            ValueError,
            CloudTrailAdapter,
            self.store,
            tenant_id="tenant-a",
            source_instance_id="unsafe-proof",
            integrity_status=CloudTrailIntegrityStatus.AWS_DIGEST_VALIDATED,
            integrity_proof_uri="s3://audit/proof.json?signature=secret",
        )

    def test_hidden_failed_login_username_is_not_exposed(self) -> None:
        record = cloudtrail_event()
        record["userIdentity"]["userName"] = "HIDDEN_DUE_TO_SECURITY_REASONS"
        event = self._ingest(record)[0]
        self.assertNotIn("user_name", event.attributes["identity"])

    def test_ndjson_bad_record_and_oversized_gzip_are_explicit(self) -> None:
        text = json.dumps(cloudtrail_event()) + "\nnot-json\n"
        events = self.adapter.ingest(
            text.encode(), media_type="application/x-ndjson", collected_at=NOW
        )
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].parse_status, ParseStatus.PARSED)
        self.assertEqual(events[1].parse_status, ParseStatus.UNPARSEABLE)

        limited = CloudTrailAdapter(
            self.store,
            tenant_id="tenant-a",
            source_instance_id="limited-trail",
            max_decompressed_bytes=16,
        )
        compressed = gzip.compress(json.dumps(cloudtrail_event()).encode())
        oversized = limited.ingest(
            compressed,
            media_type="application/gzip",
            content_encoding="gzip",
            collected_at=NOW,
        )[0]
        self.assertEqual(oversized.parse_status, ParseStatus.UNPARSEABLE)
        self.assertIn("decompressed limit", oversized.parse_warnings[0])
        self.assertEqual(self.store.get(oversized.raw_evidence), compressed)

    def test_strict_ndjson_failure_is_isolated_to_its_record(self) -> None:
        duplicate = (
            '{"eventVersion":"1.09","eventversion":"1.08",'
            '"userIdentity":{},"eventTime":"2026-08-11T11:59:00Z",'
            '"eventSource":"s3.amazonaws.com","eventName":"GetObject"}'
        )
        payload = duplicate + "\n" + json.dumps(cloudtrail_event()) + "\n"
        events = self.adapter.ingest(
            payload.encode(),
            media_type="application/x-ndjson",
            collected_at=NOW,
        )
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].parse_status, ParseStatus.UNPARSEABLE)
        self.assertEqual(events[1].parse_status, ParseStatus.PARSED)

    def test_trail_insight_links_start_end_and_attributed_principals(self) -> None:
        record = {
            "eventVersion": "1.07",
            "eventType": "AwsCloudTrailInsight",
            "eventID": "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
            "eventTime": "2026-08-11T11:50:00Z",
            "awsRegion": "us-east-1",
            "recipientAccountId": "123456789012",
            "sharedEventID": "cccccccc-4444-5555-6666-dddddddddddd",
            "eventCategory": "Insight",
            "insightDetails": {
                "state": "Start",
                "eventSource": "autoscaling.amazonaws.com",
                "eventName": "CompleteLifecycleAction",
                "insightType": "ApiCallRateInsight",
                "insightContext": {
                    "statistics": {
                        "baseline": {"average": 0.01},
                        "insight": {"average": 3.5},
                        "insightDuration": 5,
                        "baselineDuration": 10080,
                    },
                    "attributions": [
                        {
                            "attribute": "userIdentityArn",
                            "insight": [
                                {
                                    "value": (
                                        "arn:aws:sts::123456789012:"
                                        "assumed-role/DeployRole/session"
                                    ),
                                    "average": 3.5,
                                }
                            ],
                            "baseline": [],
                        }
                    ],
                },
            },
        }
        event = self._ingest(record)[0]
        self.assertEqual(event.source_type, "aws_cloudtrail_insight")
        self.assertEqual(event.parse_status, ParseStatus.PARSED)
        self.assertEqual(event.attributes["event"]["version"], "1.07")
        self.assertEqual(event.attributes["insight"]["state"], "Start")
        self.assertEqual(
            event.attributes["insight"]["statistics"]["insight_average"], 3.5
        )
        keys = {(key.kind, key.value) for key in event.entity_keys}
        self.assertIn(
            (
                "cloudtrail_insight_id",
                "cccccccc-4444-5555-6666-dddddddddddd",
            ),
            keys,
        )
        self.assertIn(
            (
                "aws_attributed_principal_arn",
                "arn:aws:sts::123456789012:assumed-role/DeployRole/session",
            ),
            keys,
        )

    def test_event_data_store_insight_shape_is_supported_separately(self) -> None:
        record = {
            "eventVersion": "1.09",
            "eventCategory": "Insight",
            "eventType": "AwsCloudTrailInsight",
            "eventID": "eeeeeeee-7777-8888-9999-ffffffffffff",
            "eventTime": "2026-08-11T11:55:00Z",
            "awsRegion": "us-east-1",
            "recipientAccountId": "123456789012",
            "sharedEventID": "01234567-89ab-cdef-0123-456789abcdef",
            "insightSource": "arn:aws:cloudtrail:us-east-1:123456789012:eventdatastore/source",
            "insightState": "End",
            "insightEventSource": "iam.amazonaws.com",
            "insightEventName": "AttachRolePolicy",
            "insightType": "ApiErrorRateInsight",
            "insightErrorCode": "AccessDenied",
            "insightContext": {
                "baselineAverage": 0.2,
                "insightAverage": 4.0,
                "baselineDuration": 10080,
                "insightDuration": 12,
                "attributions": [],
            },
        }
        event = self._ingest(record)[0]
        self.assertEqual(event.parse_status, ParseStatus.PARSED)
        self.assertEqual(event.attributes["insight"]["shape"], "event_data_store")
        self.assertEqual(event.attributes["event"]["action"], "AttachRolePolicy")
        self.assertEqual(
            event.attributes["insight"]["statistics"]["baseline_average"], 0.2
        )

    def test_special_event_shapes_with_missing_ids_are_partial_not_misclassified(self) -> None:
        insight = {
            "eventVersion": "1.07",
            "eventType": "AwsCloudTrailInsight",
            "eventTime": "2026-08-11T11:50:00Z",
            "awsRegion": "us-east-1",
            "recipientAccountId": "123456789012",
            "eventCategory": "Insight",
            "insightDetails": {
                "state": "Start",
                "eventSource": "iam.amazonaws.com",
                "eventName": "AttachRolePolicy",
                "insightType": "ApiCallRateInsight",
                "insightContext": {},
            },
        }
        insight_event = self._ingest(insight)[0]
        self.assertEqual(insight_event.source_type, "aws_cloudtrail_insight")
        self.assertEqual(insight_event.parse_status, ParseStatus.PARTIAL)
        self.assertTrue(any("eventID is missing" == w for w in insight_event.parse_warnings))
        self.assertTrue(
            any("sharedEventID is missing" == w for w in insight_event.parse_warnings)
        )

        aggregate = {
            "eventVersion": "1.0",
            "eventType": "AwsAggregatedEvent",
            "eventCategory": "Aggregated",
            "accountId": "123456789012",
            "awsRegion": "us-east-1",
            "eventSource": "cloudtrail-data.amazonaws.com",
            "timeWindow": {
                "windowStart": "2026-08-11 11:45:00",
                "windowEnd": "2026-08-11 11:50:00",
            },
            "summary": {},
        }
        aggregate_event = self._ingest(aggregate)[0]
        self.assertEqual(aggregate_event.source_type, "aws_cloudtrail_aggregated")
        self.assertEqual(aggregate_event.parse_status, ParseStatus.PARTIAL)
        self.assertTrue(any("eventId is missing" == w for w in aggregate_event.parse_warnings))

    def test_identity_center_and_delegated_provider_ids_are_scoped(self) -> None:
        record = cloudtrail_event()
        record["userIdentity"]["onBehalfOf"] = {
            "userId": "identity-center-user-1",
            "identityStoreArn": (
                "arn:aws:identitystore::123456789012:identitystore/d-example"
            ),
        }
        record["userIdentity"]["invokedByDelegate"] = {
            "accountId": "999999999999"
        }
        event = self._ingest(record)[0]
        keys = {(key.kind, key.value, key.scope) for key in event.entity_keys}
        self.assertIn(
            (
                "aws_identity_center_user_id",
                "identity-center-user-1",
                "arn:aws:identitystore::123456789012:identitystore/d-example",
            ),
            keys,
        )
        self.assertIn(
            ("aws_delegated_provider_account_id", "999999999999", "aws"), keys
        )

    def test_invalid_guid_and_oversized_request_id_are_not_correlation_keys(self) -> None:
        record = cloudtrail_event(
            event_id="not-a-cloudtrail-guid",
            request_id="r" * 1_025,
        )
        record["sharedEventID"] = "also-not-a-guid"
        event = self._ingest(record)[0]
        self.assertEqual(event.parse_status, ParseStatus.PARTIAL)
        self.assertIsNone(event.native_event_id)
        key_kinds = {key.kind for key in event.entity_keys}
        self.assertNotIn("cloudtrail_event_id", key_kinds)
        self.assertNotIn("cloudtrail_shared_event_id", key_kinds)
        self.assertNotIn("cloud_request_id", key_kinds)
        self.assertTrue(
            any("valid CloudTrail GUID" in warning for warning in event.parse_warnings)
        )
        self.assertTrue(
            any("1 KB maximum" in warning for warning in event.parse_warnings)
        )

    def test_gzip_magic_is_recognized_without_untrusted_filename_metadata(self) -> None:
        compressed = gzip.compress(json.dumps(cloudtrail_event()).encode())
        event = self.adapter.ingest(
            compressed,
            media_type="application/octet-stream",
            collected_at=NOW,
        )[0]
        self.assertEqual(event.parse_status, ParseStatus.PARSED)
        self.assertEqual(self.store.get(event.raw_evidence), compressed)

    def test_ambiguous_keys_nonfinite_numbers_and_deep_json_fail_safely(self) -> None:
        duplicate = (
            '{"eventVersion":"1.09","eventversion":"1.08",'
            '"userIdentity":{},"eventTime":"2026-08-11T11:59:00Z",'
            '"eventSource":"s3.amazonaws.com","eventName":"GetObject"}'
        ).encode()
        duplicate_event = self.adapter.ingest(
            duplicate, media_type="application/json", collected_at=NOW
        )[0]
        self.assertEqual(duplicate_event.parse_status, ParseStatus.UNPARSEABLE)
        self.assertIn("ambiguous", duplicate_event.parse_warnings[0])

        nonfinite = json.dumps(cloudtrail_event()).replace(
            '"readOnly": true', '"readOnly": NaN'
        )
        nonfinite_event = self.adapter.ingest(
            nonfinite.encode(), media_type="application/json", collected_at=NOW
        )[0]
        self.assertEqual(nonfinite_event.parse_status, ParseStatus.UNPARSEABLE)
        self.assertIn("non-finite", nonfinite_event.parse_warnings[0])

        deeply_nested = cloudtrail_event()
        nested: dict = {}
        deeply_nested["requestParameters"] = nested
        for _ in range(70):
            child: dict = {}
            nested["child"] = child
            nested = child
        deep_event = self._ingest(deeply_nested)[0]
        self.assertEqual(deep_event.parse_status, ParseStatus.UNPARSEABLE)
        self.assertIn("depth limit", deep_event.parse_warnings[0])

    def test_aggregated_event_uses_utc_window_and_resource_dimensions(self) -> None:
        record = {
            "eventVersion": "1.0",
            "accountId": "123456789012",
            "eventId": "13572468-2468-1357-8642-abcdefabcdef",
            "eventCategory": "Aggregated",
            "eventType": "AwsAggregatedEvent",
            "awsRegion": "us-east-1",
            "eventSource": "cloudtrail-data.amazonaws.com",
            "timeWindow": {
                "windowStart": "2026-08-11 11:45:00",
                "windowEnd": "2026-08-11 11:50:00",
                "windowSize": "PT5M",
            },
            "summary": {
                "primaryDimension": {
                    "dimension": "eventName",
                    "statistics": [{"name": "PutAuditEvents", "value": 30}],
                    "aggregationType": "Count",
                },
                "details": [
                    {
                        "dimension": "resourceARN",
                        "statistics": [
                            {
                                "name": (
                                    "arn:aws:cloudtrail:us-east-1:123456789012:"
                                    "channel/channel-id"
                                ),
                                "value": 30,
                            }
                        ],
                        "aggregationType": "Count",
                    }
                ],
            },
        }
        event = self._ingest(record)[0]
        self.assertEqual(event.source_type, "aws_cloudtrail_aggregated")
        self.assertEqual(event.parse_status, ParseStatus.PARSED)
        self.assertEqual(event.observed_at.tzinfo, timezone.utc)
        self.assertEqual(event.attributes["aggregation"]["window_size"], "PT5M")
        keys = {(key.kind, key.value) for key in event.entity_keys}
        self.assertIn(
            (
                "aws_resource_arn",
                "arn:aws:cloudtrail:us-east-1:123456789012:channel/channel-id",
            ),
            keys,
        )


if __name__ == "__main__":
    unittest.main()
