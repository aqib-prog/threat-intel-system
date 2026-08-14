from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

from correlation.models import (
    CORRELATION_EVENT_SCHEMA_VERSION,
    EntityKey,
    EventTimeQuality,
    NormalizedEvent,
    ParseStatus,
    Platform,
    RawEvidenceRef,
)


NOW = datetime(2026, 8, 4, 10, 30, tzinfo=timezone.utc)


def _raw(payload: bytes = b'{"event": "test"}') -> RawEvidenceRef:
    return RawEvidenceRef.for_bytes(
        payload,
        uri="file:///evidence/sha256/test",
        media_type="application/json",
        collected_at=NOW,
    )


def _event(**overrides) -> NormalizedEvent:
    values = {
        "event_id": "evt-001",
        "tenant_id": "tenant-local",
        "platform": Platform.WINDOWS,
        "source_type": "sysmon",
        "source_instance_id": "host-01",
        "adapter_version": "1.0.0",
        "observed_at": NOW - timedelta(seconds=1),
        "ingested_at": NOW,
        "event_time_quality": EventTimeQuality.SOURCE_REPORTED,
        "parse_status": ParseStatus.PARSED,
        "raw_evidence": _raw(),
        "native_event_id": "{event-guid}",
        "entity_keys": (
            EntityKey(kind="process_guid", value="{process-guid}", scope="host-01:boot-1"),
        ),
        "attributes": {"process": {"pid": 42, "args": ["cmd.exe", "/c", "whoami"]}},
    }
    values.update(overrides)
    return NormalizedEvent(**values)


class RawEvidenceRefTests(unittest.TestCase):
    def test_reference_is_content_addressed_and_serializable(self) -> None:
        reference = _raw(b"raw bytes")

        self.assertEqual(
            reference.sha256,
            "9ab366ad455508d5f47b0128d7d243a2c0e4f5ce399b5f85cd10b343e745a4dc",
        )
        self.assertEqual(reference.evidence_id, f"sha256:{reference.sha256}")
        self.assertEqual(reference.byte_length, 9)
        self.assertEqual(reference.to_dict()["collected_at"], NOW.isoformat())

    def test_reference_rejects_naive_time_and_bad_digest(self) -> None:
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            RawEvidenceRef(
                sha256="0" * 64,
                uri="file:///raw",
                byte_length=1,
                media_type="application/json",
                collected_at=datetime(2026, 8, 4),
            )
        with self.assertRaisesRegex(ValueError, "64-character"):
            RawEvidenceRef(
                sha256="not-a-digest",
                uri="file:///raw",
                byte_length=1,
                media_type="application/json",
                collected_at=NOW,
            )


class EntityKeyTests(unittest.TestCase):
    def test_platform_keys_are_explicitly_scoped(self) -> None:
        keys = {
            EntityKey("process_guid", "{guid}", "windows-host:boot"),
            EntityKey("process_pidversion", "501:9", "mac-host:boot"),
            EntityKey("audit_process", "host:p123", "linux-host:boot"),
            EntityKey("cloud_request_id", "request-1", "aws-account:region"),
            EntityKey("kubernetes_audit_id", "audit-1", "cluster-uid"),
        }
        self.assertEqual(len(keys), 5)

    def test_secret_and_unhashed_token_keys_are_rejected(self) -> None:
        for kind in ("password", "client_secret", "bearer_token", "session_token"):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                EntityKey(kind, "sensitive", "scope")

        safe = EntityKey("session_token_hmac", "hmac-value", "tenant-key-v1")
        self.assertEqual(safe.kind, "session_token_hmac")

        macos_identity = EntityKey("audit_token", "pid:pidversion", "host:boot")
        self.assertEqual(macos_identity.kind, "audit_token")


class NormalizedEventTests(unittest.TestCase):
    def test_every_supported_platform_uses_the_same_contract(self) -> None:
        for platform in Platform:
            with self.subTest(platform=platform):
                event = _event(platform=platform, event_id=f"evt-{platform.value}")
                self.assertEqual(event.platform, platform)
                self.assertEqual(event.schema_version, CORRELATION_EVENT_SCHEMA_VERSION)

    def test_envelope_is_immutable_and_copies_nested_attributes(self) -> None:
        attributes = {"process": {"args": ["one"]}}
        event = _event(attributes=attributes)
        attributes["process"]["args"].append("mutated")

        self.assertEqual(event.to_dict()["attributes"], {"process": {"args": ["one"]}})
        with self.assertRaises(FrozenInstanceError):
            event.event_id = "changed"  # type: ignore[misc]
        with self.assertRaises(TypeError):
            event.attributes["new"] = "value"  # type: ignore[index]

    def test_duplicate_entity_keys_are_removed_without_reordering(self) -> None:
        first = EntityKey("process_guid", "one", "host:boot")
        second = EntityKey("user_session", "two", "host:boot")
        event = _event(entity_keys=(first, second, first))
        self.assertEqual(event.entity_keys, (first, second))

    def test_time_quality_cannot_contradict_timestamp(self) -> None:
        with self.assertRaisesRegex(ValueError, "requires observed_at"):
            _event(observed_at=None)
        with self.assertRaisesRegex(ValueError, "must not carry observed_at"):
            _event(event_time_quality=EventTimeQuality.UNKNOWN)

        unknown = _event(
            observed_at=None,
            event_time_quality=EventTimeQuality.UNKNOWN,
        )
        self.assertEqual(unknown.effective_event_time, NOW)

    def test_unparseable_event_preserves_raw_reference_without_fake_fields(self) -> None:
        event = _event(
            observed_at=None,
            event_time_quality=EventTimeQuality.UNKNOWN,
            parse_status=ParseStatus.UNPARSEABLE,
            attributes={},
            parse_warnings=("invalid JSON",),
            entity_keys=(),
        )
        self.assertEqual(event.raw_evidence.evidence_id, _raw().evidence_id)
        self.assertEqual(event.to_dict()["parse_warnings"], ["invalid JSON"])

        with self.assertRaisesRegex(ValueError, "cannot claim"):
            _event(
                parse_status=ParseStatus.UNPARSEABLE,
                attributes={"invented": True},
            )

    def test_fully_parsed_event_rejects_parse_warnings(self) -> None:
        with self.assertRaisesRegex(ValueError, "fully parsed"):
            _event(parse_warnings=("should not exist",))

    def test_non_json_attribute_types_are_rejected(self) -> None:
        with self.assertRaisesRegex(TypeError, "JSON-compatible"):
            _event(attributes={"bad": object()})

    def test_direct_construction_rejects_untyped_or_unknown_contract_values(self) -> None:
        with self.assertRaisesRegex(TypeError, "platform must"):
            _event(platform="windows")  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "unsupported"):
            _event(schema_version="2.0.0")

        serialized = _event().to_dict()
        serialized["entity_keys"] = ["not-an-object"]
        with self.assertRaisesRegex(ValueError, "entry must be an object"):
            NormalizedEvent.from_dict(serialized)

    def test_serialization_round_trip_is_lossless(self) -> None:
        event = _event()
        restored = NormalizedEvent.from_dict(event.to_dict())
        self.assertEqual(restored, event)


if __name__ == "__main__":
    unittest.main()
