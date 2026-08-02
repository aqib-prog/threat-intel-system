"""Read-only graph neighbourhood lookup for the UI's relationship explorer.

Deliberately isolated from the answering pipeline. This router shares no code
path with ``/query``: it does not call the guardrail, the retriever, the
reranker, or generation, and it never writes. It exists so the UI can draw the
REAL neighbourhood of a node straight from Neo4j, rather than inferring
relationships from answer prose.

Isolation is the point. The endpoint is only reached when a user clicks a node
in an answer that has already been produced. If Neo4j is unreachable or the id
does not resolve, this returns a clean error and the answer already on screen is
completely unaffected - nothing here can degrade normal answering.
"""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from orchestration.pipeline import get_driver
from security import limiter, require_api_key


router = APIRouter(prefix="/graph", tags=["graph"])

# Matches the identifier shapes the graph actually stores. Anchored and
# length-bounded: the value is interpolated nowhere - it is always passed as a
# query PARAMETER below - but validating early gives a 422 instead of a
# pointless database round trip for obviously malformed input.
EXTERNAL_ID_RE = re.compile(r"^(?:TA|DET|DC|DS|AN|T|G|S|M|C)\d{4}(?:\.\d{3})?$", re.IGNORECASE)

# Human-readable direction-aware labels. The same edge means different things
# depending on which end the anchor sits at ("uses" vs "used by"), and showing
# the wrong one would misrepresent the graph.
RELATIONSHIP_LABELS: dict[tuple[str, str], str] = {
    ("USES", "out"): "Uses",
    ("USES", "in"): "Used by",
    ("MITIGATES", "out"): "Mitigates",
    ("MITIGATES", "in"): "Mitigated by",
    ("DETECTS", "out"): "Detects",
    ("DETECTS", "in"): "Detected by",
    ("ATTRIBUTED_TO", "out"): "Attributed to",
    ("ATTRIBUTED_TO", "in"): "Attributed campaigns",
    ("BELONGS_TO_TACTIC", "out"): "Belongs to tactic",
    ("BELONGS_TO_TACTIC", "in"): "Techniques in tactic",
    ("SUBTECHNIQUE_OF", "out"): "Parent technique",
    ("SUBTECHNIQUE_OF", "in"): "Subtechniques",
    ("HAS_ANALYTIC", "out"): "Analytics",
    ("HAS_ANALYTIC", "in"): "Detection strategy",
    ("USES_DATA_COMPONENT", "out"): "Data components",
    ("USES_DATA_COMPONENT", "in"): "Used by analytics",
}

# One hop only, and capped. A hub node (a popular tactic) can have hundreds of
# neighbours; returning them all would produce an unreadable diagram and a slow
# response. The cap is per relationship group so no single dense edge type can
# crowd out the others.
PER_GROUP_LIMIT = 12
MAX_TOTAL_NEIGHBORS = 60

NEIGHBOR_CYPHER = """
MATCH (anchor:MitreNode {external_id: $external_id})
OPTIONAL MATCH (anchor)-[r]-(neighbor:MitreNode)
WHERE neighbor.external_id IS NOT NULL
RETURN
  anchor.name          AS anchor_name,
  anchor.external_id   AS anchor_id,
  labels(anchor)       AS anchor_labels,
  type(r)              AS rel_type,
  startNode(r) = anchor AS outgoing,
  neighbor.name        AS neighbor_name,
  neighbor.external_id AS neighbor_id,
  labels(neighbor)     AS neighbor_labels
"""


class GraphNode(BaseModel):
    name: str
    external_id: str
    node_type: str


class GraphGroup(BaseModel):
    """One relationship type, in one direction, with its neighbours."""

    relationship: str
    label: str
    direction: str
    nodes: list[GraphNode]
    truncated: bool = False


class GraphNeighborsResponse(BaseModel):
    anchor: GraphNode
    groups: list[GraphGroup]
    total: int


def _node_type(labels: list[str] | None) -> str:
    """Pick the specific label, ignoring the shared `MitreNode` marker."""
    for label in labels or []:
        if label != "MitreNode":
            return label
    return "MitreNode"


@router.get("/neighbors/{external_id}", response_model=GraphNeighborsResponse)
@limiter.limit("30/minute")
def graph_neighbors(
    request: Request,
    external_id: str,
    _: None = Depends(require_api_key),
) -> GraphNeighborsResponse:
    """Return the one-hop neighbourhood of a node, grouped by relationship."""
    identifier = (external_id or "").strip().upper()
    if not EXTERNAL_ID_RE.match(identifier):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Not a valid MITRE identifier.",
        )

    try:
        driver = get_driver()
        with driver.session() as session:
            records = list(session.run(NEIGHBOR_CYPHER, external_id=identifier))
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 - surfaced as a clean 503
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Graph is unavailable right now.",
        ) from exc

    if not records:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{identifier} is not in the knowledge graph.",
        )

    first = records[0]
    anchor = GraphNode(
        name=first["anchor_name"] or identifier,
        external_id=first["anchor_id"] or identifier,
        node_type=_node_type(first["anchor_labels"]),
    )

    grouped: dict[tuple[str, str], list[GraphNode]] = {}
    seen: set[tuple[str, str, str]] = set()
    for record in records:
        rel_type = record["rel_type"]
        neighbor_id = record["neighbor_id"]
        if not rel_type or not neighbor_id:
            continue  # OPTIONAL MATCH yields a null row for an isolated node
        direction = "out" if record["outgoing"] else "in"
        key = (rel_type, direction)
        # The same pair can appear twice when two nodes are linked more than
        # once; a diagram must show each neighbour under a group only once.
        dedupe = (rel_type, direction, neighbor_id)
        if dedupe in seen:
            continue
        seen.add(dedupe)
        grouped.setdefault(key, []).append(
            GraphNode(
                name=record["neighbor_name"] or neighbor_id,
                external_id=neighbor_id,
                node_type=_node_type(record["neighbor_labels"]),
            )
        )

    groups: list[GraphGroup] = []
    total = 0
    for (rel_type, direction), nodes in grouped.items():
        nodes.sort(key=lambda item: item.external_id)
        truncated = len(nodes) > PER_GROUP_LIMIT
        capped = nodes[:PER_GROUP_LIMIT]
        total += len(capped)
        groups.append(
            GraphGroup(
                relationship=rel_type,
                label=RELATIONSHIP_LABELS.get(
                    (rel_type, direction), rel_type.replace("_", " ").title()
                ),
                direction=direction,
                nodes=capped,
                truncated=truncated,
            )
        )

    # Largest groups first so the densest, most informative relationship leads.
    groups.sort(key=lambda group: len(group.nodes), reverse=True)
    if total > MAX_TOTAL_NEIGHBORS:
        kept: list[GraphGroup] = []
        running = 0
        for group in groups:
            if running >= MAX_TOTAL_NEIGHBORS:
                break
            room = MAX_TOTAL_NEIGHBORS - running
            if len(group.nodes) > room:
                group = group.model_copy(
                    update={"nodes": group.nodes[:room], "truncated": True}
                )
            kept.append(group)
            running += len(group.nodes)
        groups, total = kept, running

    return GraphNeighborsResponse(anchor=anchor, groups=groups, total=total)
