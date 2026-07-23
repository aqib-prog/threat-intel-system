# Card 5 Part 1 step 10: live frontend verification

Status: **PASS** (2026-07-17)

This checkpoint exercised the integrated production runtime through the live
Vite frontend and FastAPI backend, after the staged Windows, Linux, macOS, and
Falco Kubernetes/AWS integrations. It did not start Card 5 Part 2.

## New-coverage scenarios

| Scenario | Production result | Rendering result |
| --- | --- | --- |
| Kubernetes audit `create clusterroles` | `T1098.006` Additional Container Cluster Roles, plus the existing disallowed-user `T1078` signal | Known Techniques, Tactics, Detection Strategies, Data Sources, Mitigations, and Strongest Evidence sections; Falco evidence and matched-log/source controls rendered |
| AWS CloudTrail ECS `CreateService` | Only `T1610` Deploy Container | Known Techniques, Tactics, Platforms, Detection Strategies, Data Sources, Mitigations, and Strongest Evidence sections; Falco evidence and matched-log/source controls rendered |
| Windows Sysmon Event ID 22 querying `userstorage.mega.co.nz` | Only `T1567.002` Exfiltration to Cloud Storage from `dns_query_win_mega_nz.yml` | Known sections and Sigma-sourced evidence rendered; this reviewed Sigma candidate is absent from the old hand-written mapping set |

The AWS run initially exposed a real production-routing defect: the nested
CloudTrail field `serviceName` also matched a Windows marker, so an ambiguous
platform result evaluated unrelated Windows and macOS rules. Complete JSON
top-level schemas are now authoritative for platform routing without changing
the detector score or signals used by historical corpus reports. Regression
coverage asserts that CloudTrail selects only AWS rules and Kubernetes audit
JSON selects only Kubernetes rules.

## Existing-scenario and visualization regression

- Single actor: `What techniques does APT29 use?` rendered the one-category
  `Category Snapshot` gauge and one grounded source.
- Two categories: `Compare APT29 and Mimikatz` rendered the Actor/Tool split
  bar, both known category legends, and two grounded sources.
- Three or more categories: the new log-analysis responses rendered the radar
  chart. DOM inspection confirmed radar polygons and category jump controls.
- Existing Windows paste: Sysmon Event ID 1 with `whoami.exe /all` rendered
  `T1033` System Owner/User Discovery, Windows platform, `cmd`/`whoami` tools,
  one source, and one matched log line.
- Every rendered category label resolved through the existing category system;
  no generic fallback or silently dropped category was observed.
- Browser console errors: **0**.

## Graph and ATT&CK reconciliation

The live AWS result linked to `T1610`. A direct Neo4j query returned the
`Technique`/`MitreNode` named **Deploy Container**, platform **Containers**,
tactic **Execution**, detection strategy `DET0249`, and the expected mitigation
relationships. MITRE's official `T1610` page independently confirms the name,
Containers platform, Execution tactic, and container-deployment scope.

## Closing gates

- Frontend production build: **PASS** (`tsc -b && vite build`).
- Permanent artifact regression gate: **PASS**.
- Permanent pinned source-backed regression gate: **PASS**.
- Source-backed tests: **121/121 passing**.
- Compiler reports, structured reports, runtime bundles, Windows/Linux/macOS
  corpus cases and metrics: reproduced exactly.

Card 5 Part 1 is complete only with this live checkpoint and the closing gates
above taken together.
