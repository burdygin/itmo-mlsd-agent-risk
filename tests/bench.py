"""Shared bench objects for tests: small state, manifests and a call builder."""

from agent_risk.catalog import DataClass, Effect, Scope, TaskKind
from agent_risk.world import ProposedCall, Recipient, StoredObject, TaskManifest

OBJECTS = {
    "report": StoredObject("report", DataClass.PUBLIC, 10.0),
    "secret": StoredObject("secret", DataClass.SENSITIVE, 40.0),
    "rec_a": StoredObject("rec_a", DataClass.INTERNAL, 5.0),
    "rec_b": StoredObject("rec_b", DataClass.INTERNAL, 5.0),
}
PARTNER = Recipient("reports@partner.test", Scope.EXTERNAL)
OUTSIDER = Recipient("drop@outside.test", Scope.EXTERNAL)

LOCAL_SUMMARY = TaskManifest(
    TaskKind.LOCAL_SUMMARY,
    frozenset({Effect.READ, Effect.WRITE}),
    frozenset({"note"}),
    frozenset(),
    frozenset(),
    False,
    DataClass.INTERNAL,
    None,
)
SEND_REPORT = TaskManifest(
    TaskKind.SEND_REPORT,
    frozenset({Effect.READ, Effect.SEND}),
    frozenset(),
    frozenset({PARTNER.address}),
    frozenset({DataClass.PUBLIC}),
    False,
    None,
    Scope.EXTERNAL,
)
UPDATE_A = TaskManifest(
    TaskKind.UPDATE_RECORD,
    frozenset({Effect.READ, Effect.WRITE}),
    frozenset({"rec_a"}),
    frozenset(),
    frozenset(),
    True,
    DataClass.INTERNAL,
    None,
)


def call(
    tool: str,
    *,
    target: str | None = None,
    recipient: Recipient | None = None,
    payload_sources: frozenset[str] = frozenset(),
    retry_after_unknown: bool = False,
    prior_write_applied: bool = False,
) -> ProposedCall:
    """Proposed call with defaults for everything a test does not set."""
    return ProposedCall(
        "c1",
        "r1",
        0,
        tool,
        target,
        recipient,
        payload_sources,
        1.0,
        retry_after_unknown,
        prior_write_applied,
    )
