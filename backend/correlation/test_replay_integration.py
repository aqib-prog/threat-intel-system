from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from correlation.aws import CloudTrailAdapter
from correlation.kubernetes import KubernetesAuditAdapter
from correlation.linux import LinuxAdapter
from correlation.local import LocalEventJournal, LocalRawEvidenceStore
from correlation.macos import MacOSAdapter
from correlation.replay import CorrelationReplayRunner
from correlation.replay_local import LocalReplayArchive
from correlation.test_aws import NOW as AWS_NOW
from correlation.test_aws import cloudtrail_event
from correlation.test_kubernetes import NOW as KUBERNETES_NOW
from correlation.test_kubernetes import audit_event
from correlation.test_linux import NOW as LINUX_NOW
from correlation.test_macos import NOW as MACOS_NOW
from correlation.test_macos import _process
from correlation.test_windows import NOW as WINDOWS_NOW
from correlation.test_windows import PROCESS_GUID, _sysmon_event
from correlation.windows import WindowsAdapter


class CrossPlatformReplayIntegrationTests(unittest.TestCase):
    def test_adapters_journal_replay_and_archive_without_live_coupling(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = LocalRawEvidenceStore(root / "evidence")
            journal = LocalEventJournal(root / "events.jsonl")

            windows = WindowsAdapter(
                evidence,
                tenant_id="tenant-a",
                source_instance_id="windows-1",
                boot_id="boot-1",
            )
            windows_records = [
                _sysmon_event(
                    1,
                    1,
                    UtcTime="2026-08-04 12:59:58.000",
                    ProcessGuid=PROCESS_GUID,
                    ProcessId="100",
                    ParentProcessId="4",
                    Image=r"C:\Windows\System32\cmd.exe",
                ),
                _sysmon_event(
                    3,
                    2,
                    ProcessGuid=PROCESS_GUID,
                    ProcessId="100",
                    Image=r"C:\Windows\System32\cmd.exe",
                    DestinationIp="203.0.113.10",
                    DestinationPort="443",
                ),
            ]
            events = []
            for record in windows_records:
                events.extend(
                    windows.ingest(
                        json.dumps(record).encode(),
                        media_type="application/json",
                        collected_at=WINDOWS_NOW,
                    )
                )

            linux = LinuxAdapter(
                evidence,
                tenant_id="tenant-a",
                source_instance_id="linux-1",
                boot_id="boot-1",
            )
            linux_payload = "\n".join(
                (
                    "type=SYSCALL msg=audit(1618347101.412:2045): "
                    "syscall=59 success=yes ppid=1204 pid=3412",
                    "type=EXECVE msg=audit(1618347101.412:2045): "
                    'argc=2 a0="id" a1="-u"',
                )
            )
            events.extend(
                linux.ingest(
                    linux_payload.encode(),
                    media_type="text/plain",
                    collected_at=LINUX_NOW,
                )
            )

            macos = MacOSAdapter(
                evidence,
                tenant_id="tenant-a",
                source_instance_id="macos-1",
                boot_id="boot-1",
                collector_instance_id="es-client-1",
            )
            target = _process(100, 8, "/usr/bin/whoami")
            macos_record = {
                "schema_version": 1,
                "version": 4,
                "time": {"sec": 1785859199, "nsec": 0},
                "seq_num": 19,
                "global_seq_num": 201,
                "process": _process(100, 7, "/bin/zsh"),
                "event": {"exec": {"target": target, "args": ["whoami"]}},
            }
            events.extend(
                macos.ingest(
                    json.dumps(macos_record).encode(),
                    media_type="application/json",
                    collected_at=MACOS_NOW,
                )
            )

            aws = CloudTrailAdapter(
                evidence,
                tenant_id="tenant-a",
                source_instance_id="organization-trail",
                allowed_recipient_account_ids=("123456789012",),
                allowed_regions=("us-east-1",),
            )
            events.extend(
                aws.ingest(
                    json.dumps(cloudtrail_event()).encode(),
                    media_type="application/json",
                    collected_at=AWS_NOW,
                )
            )

            kubernetes = KubernetesAuditAdapter(
                evidence,
                tenant_id="tenant-a",
                source_instance_id="audit-webhook-1",
                cluster_uid="cluster-1",
            )
            received = audit_event(stage="RequestReceived")
            received.pop("responseStatus")
            received.pop("responseObject")
            received["stageTimestamp"] = received[
                "requestReceivedTimestamp"
            ]
            events.extend(
                kubernetes.ingest(
                    json.dumps(
                        {
                            "kind": "EventList",
                            "apiVersion": "audit.k8s.io/v1",
                            "items": [received, audit_event()],
                        }
                    ).encode(),
                    media_type="application/json",
                    collected_at=KUBERNETES_NOW,
                )
            )

            for event in events:
                journal.publish(event)

            result = CorrelationReplayRunner().run(journal)
            archive = LocalReplayArchive(root / "replays")
            report_id = archive.put(result)
            report = archive.get_report(report_id).to_dict()

            self.assertEqual(len(events), 8)
            self.assertEqual(len(result.deterministic_snapshot.incidents), 5)
            self.assertEqual(report["artifacts"]["incidents"]["count"], 5)
            self.assertEqual(
                set(
                    report["coverage"]["deterministic_edges"][
                        "platform_counts"
                    ]
                ),
                {"aws", "kubernetes", "linux", "macos", "windows"},
            )
            self.assertEqual(result.heuristic_edges.edges, ())
            self.assertFalse(report["accuracy_measured"])


if __name__ == "__main__":
    unittest.main()
