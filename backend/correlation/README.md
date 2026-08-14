# Correlation subsystem

This package will provide cross-platform, multi-event correlation without
changing the existing single-event `log_analysis` or GraphRAG behavior.

## Non-negotiable boundaries

1. Sensor bytes are durably stored before parsing. A parser failure cannot
   delete or replace the evidence.
2. Normalized events reference immutable raw evidence by SHA-256 and URI; they
   never pretend to be the raw source.
3. Tenant identity is assigned by trusted ingestion configuration, never read
   from an untrusted event payload.
4. Event occurrence time, ingestion time, and timestamp quality remain
   separate.
5. Native identifiers are scoped to the host boot, cloud account/region,
   cluster, or other namespace in which they are actually unique.
6. Passwords, secrets, and bearer tokens are never correlation keys. A
   sensitive value may only contribute through a tenant-keyed HMAC when that
   platform's validated design genuinely requires it.
7. Replay and live ingestion use the same `NormalizedEvent` contract and the
   same correlation engine.
8. Existing ATT&CK mapping remains an enrichment step. Neo4j is not the hot
   telemetry or stream-processing state store.
9. Test labels and orchestration markers remain out-of-band and are never
   available to production correlation rules.
10. Local and production infrastructure implement the ports in `ports.py`;
    correlation domain logic never imports a specific bus or state-store SDK.

## Windows adapter

`windows.py` accepts structured JSON/NDJSON produced by a trusted Windows
collector and exported Windows Event XML. It uses Sysmon `ProcessGuid` and
`ParentProcessGuid` where present, while PID-only Security events remain
explicitly typed so later correlation can account for PID reuse. All native
identifiers are scoped to the trusted source host and boot identifier.

Native binary EVTX is preserved as immutable evidence but must be decoded by
the collection tier before normalization. This keeps a complex binary decoder
out of the security boundary without dropping evidence or pretending an
unsupported payload was understood.

## Linux adapter

`linux.py` supports native auditd lines, journald JSON carrying native audit
messages, structured Auditbeat-style JSON, and Sysmon for Linux XML/JSON.
Linux Audit records remain separate envelopes and share a boot-scoped
`audit_event_serial` key. This matches Linux Audit's compound-event semantics
while avoiding the incorrect use of an audit serial, `auid`, or `ses` as a
persistent process identity. Sysmon `ProcessGuid` remains the preferred stable
process key when that sensor supplies it.

## macOS adapter

`macos.py` supports JSON Lines from Apple's `eslogger` prototype collector and
structured Elastic ECS endpoint events. Endpoint Security process identity is
the host-and-boot-scoped `(pid, pidversion)` tuple from an audit token; Elastic
events use `process.entity_id` when supplied. `seq_num` and `global_seq_num`
remain collector-loss metadata scoped to a configured collector instance and
are never treated as entity identities. Fields introduced in later Endpoint
Security message versions are ignored below their documented version gate.

Apple explicitly states that `eslogger` JSON is not a stable API. A production
native Endpoint Security client can replace the prototype collector while
emitting this same normalized contract. `eslogger` captures notify events only,
cannot observe authorization-denied attempts, and XPC/UIPC events are not
misrepresented as TCP/UDP network telemetry.

## AWS adapter

`aws.py` accepts standard CloudTrail `Records` objects, single records, arrays,
NDJSON, and bounded gzip-compressed S3 log files. Management, data, network,
service, trail/Lake Insights, and aggregated-event record shapes are handled
without forcing them through one API-call schema. It preserves compressed bytes
before decompression. `eventID`, `sharedEventID`, and service-generated
`requestID` values remain separate keys with their documented scopes;
cross-account recipient and caller accounts are not conflated. Identity,
session, resource ARN, VPC endpoint, and addendum links are normalized without
copying arbitrary request or response bodies that may contain credentials.

CloudTrail digest validation is not guessed from an event. A trusted collector
may mark an S3 object `aws_digest_validated` only with a validation-proof URI;
live sources and unvalidated objects remain explicitly distinct. Unknown major
event-schema versions are retained as raw evidence but not interpreted.

## Kubernetes adapter

`kubernetes.py` accepts `audit.k8s.io/v1` Event objects, EventLists, JSON
arrays, NDJSON log output, and bounded gzip transport. Every request stage is
kept as a separate evidence occurrence; the trusted-cluster-scoped `auditID`
is the key that joins `RequestReceived`, `ResponseStarted`,
`ResponseComplete`, and `Panic` records. Object UIDs, authenticated identities,
and impersonated identities remain distinct correlation keys.

Request and response objects, arbitrary `user.extra` values, unrecognized
audit annotations, response messages, and request query values are retained
only in immutable raw evidence because they can carry credentials or
attacker-controlled content. The final source IP is recorded as the API
server's reported transport peer, while preceding forwarded addresses and the
client-supplied user agent are explicitly marked untrusted. Unknown audit API
versions are preserved but not interpreted.

## Deterministic native-key edges

`edges.py` converts normalized events into tenant-scoped, bipartite
event-to-entity edges. It never expands a shared key into every possible
event-to-event pair, so a busy identity or resource cannot cause quadratic
growth.

Only lifetime-stable request, process, session, and activity identifiers may
drive correlation. Examples include Sysmon process GUIDs, macOS process
`(pid, pidversion)` identities, Linux audit serials, CloudTrail event/request
IDs, Windows activity/logon IDs, and Kubernetes audit IDs. Parent, related,
original, initiator, and responsible keys canonicalize to the same entity kind
while retaining their explicit role.

Exact but long-lived identities and resources are emitted as context-only
edges. They can enrich a future incident but cannot merge all activity by one
user, IAM role, access key, Kubernetes object, or resource into an incident.
Bare PIDs and mutable Kubernetes usernames are excluded because they are not
stable identities. Unknown future adapter keys and all keys on unparseable
events fail closed.

Coverage reports parsed/partial/unparseable events, correlation-capable versus
context-only events, excluded and unknown keys, and per-platform counts. Edge
IDs and returned ordering are deterministic, redelivery of an identical event
is idempotent, conflicting reuse of a tenant/event ID is rejected, and hard
event/edge limits bound in-memory construction.

## Versioned, reversible incident components

`incidents.py` builds connected components from correlation-driving edges
only. In this layer, an incident means a correlated candidate component; it is
not by itself a claim that an attack occurred. Context edges are attached only
after component membership is fixed, so shared users, roles, access keys, and
resources cannot silently merge unrelated activity.

Incident events are ordered by effective event time with deterministic
tie-breakers. Each incident records the exact correlation and context edge IDs
that justify its content, canonical entity keys, stable normalized-event
digests, platform set, and time range. Platform is part of the internal entity
namespace, preventing an accidental source-scope collision from joining (for
example) Windows and Linux process GUIDs.

Every incident, snapshot, and revision is immutable and content-addressed.
Snapshots explicitly retain events that have no eligible correlation edge as
unassigned. Revisions distinguish newly assigned, newly unassigned, newly
observed, and removed events, and classify component changes as create,
remove, expand, contract, update, merge, split, or recompose. Rollback appends
a new revision pointing to an earlier immutable snapshot; it never rewrites
history. Validated serialization supports replacing the in-memory reference
history with any implementation of the `IncidentHistoryStore` port.

`incident_local.py` supplies the durable single-node implementation. It uses
an append-only JSONL journal with content validation, process/thread locking,
atomic complete-record semantics, fsync support, symlink rejection, restart
recovery, and safe removal of only a crash-truncated final record. A staging or
production database implementation changes configuration and the storage port,
not incident membership or revision semantics.

## Bounded heuristic edges

`heuristics.py` defines a separate heuristic edge type that
`IncidentBuilder` cannot consume. Heuristics are disabled by default,
shadow-only when explicitly enabled, and marked `unmeasured`; they cannot
claim production confidence before replay against independently labeled
multi-event data.

The first provisional rule considers temporal parent-PID lineage for degraded
Windows, Linux, and macOS telemetry only. It requires source-reported time, a
recognized process-start/exec action, an exact tenant/platform/host-boot scope,
a strictly earlier parent observation inside an explicitly configured window,
and exactly one candidate. A stable parent GUID, entity ID, or `(pid,
pidversion)` supersedes the heuristic. Equal timestamps, multiple live PID
candidates, unsupported platforms, collector-assigned time, unparseable
events, and out-of-window candidates all fail closed and are counted.

The configured window has a hard five-minute safety ceiling, with explicit
event, edge, PID-index, and per-PID candidate limits. AWS principal/resource
associations and Kubernetes users/objects are intentionally excluded: their
shared presence is context, not sufficient evidence of one incident.

`shadow.py` compares these proposals to an immutable deterministic incident
snapshot without modifying it. It reports whether each edge would be
redundant, merge incidents, attach unassigned evidence, or create a new
component. Transitive proposals are bounded by explicit incident/event blast
radius limits. Every component remains `promotion_eligible=false` with an
`unmeasured_rule` suppression reason, even when it is within those limits.

## Replay measurement

`replay.py` consumes the infrastructure-neutral `EventReplaySource` port once,
applies bounded deterministic edge and incident builders, and then runs the
optional heuristic policy through the read-only shadow comparator. Its
content-addressed report includes exact edge, incident, unassigned-event,
heuristic, and shadow-component counts/digests plus coverage and policy values.
It contains a bounded review sample; the returned immutable replay result keeps
the complete ordered artifacts available to a caller or durable sink without
duplicating them into an unbounded summary document.

The report explicitly records `ground_truth_supplied=false`,
`accuracy_measured=false`, deterministic-only incident membership, and
non-promotable heuristics. Those fields are integrity-checked. A corpus replay
therefore measures behavior and blast radius without being misrepresented as
precision/recall evidence.

`replay_local.py` is the single-node implementation of the `ReplayArchive`
port. It atomically publishes an immutable, content-addressed report directory
and separate complete JSONL streams for heuristic edges, edge assessments, and
shadow components. Reads reject symlinks, oversized files, incomplete or
non-canonical records, count changes, and digest mismatches. Distributed
storage can replace this port without changing replay or correlation rules.

## Independent correlation ground truth

`ground_truth.py` defines content-addressed expected components and computes
exact pairwise precision, recall, and F1 for both deterministic membership and
the shadow proposal. The scorer uses component-intersection counts rather than
enumerating every event pair, so it does not become quadratic on long runs.

Scoring requires an exhaustive event assignment. A score qualifies as
promotion evidence only when labels came from a capture orchestrator, each
label has a native-event-ID or injected-marker join, the capture contains
benign background activity, and assignment is exhaustive. Post-hoc analyst,
detector-derived, and time-window labels remain useful diagnostics but cannot
authorize heuristic promotion.

## Incremental implementation sequence

1. Immutable local evidence store and replay journal (`local.py`).
2. Platform adapters, each validated independently.
3. Deterministic native-key edges and coverage accounting.
4. Versioned, reversible incidents.
5. Explicitly bounded heuristic edges.
6. Read-only replay and shadow measurement.
7. Chatbot/frontend integration only after independently labeled validation.

The local prototype uses lightweight implementations of the infrastructure
ports. Staging and production replace those implementations through
configuration while keeping event schemas, rules, incident semantics, and
tests unchanged.
