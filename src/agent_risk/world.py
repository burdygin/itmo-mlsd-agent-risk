"""Hidden state of the test bench: objects, verified task manifest and proposed calls.

The oracle reads these exact values. The gateway sees only a degraded view of them,
built in :mod:`agent_risk.gateway`.
"""

from dataclasses import dataclass

from agent_risk.catalog import DataClass, Effect, Scope, TaskKind


@dataclass(frozen=True, slots=True)
class StoredObject:
    """Fictitious document or record of the bench organisation."""

    object_id: str
    data_class: DataClass
    size_kb: float


@dataclass(frozen=True, slots=True)
class Recipient:
    """Fictitious recipient address and whether it is inside the organisation."""

    address: str
    scope: Scope


@dataclass(frozen=True, slots=True)
class TaskManifest:
    """Constraints fixed by the scenario owner before any call is generated.

    ``write_class`` and ``recipient_scope`` are the coarse description that a gateway
    with an incomplete manifest still receives.
    """

    kind: TaskKind
    allowed_effects: frozenset[Effect]
    allowed_write_objects: frozenset[str]
    allowed_recipients: frozenset[str]
    allowed_send_classes: frozenset[DataClass]
    exactly_once: bool
    write_class: DataClass | None
    recipient_scope: Scope | None


@dataclass(frozen=True, slots=True)
class ProposedCall:
    """Tool call proposed by the agent, with its true arguments and provenance.

    ``payload_sources`` lists objects whose content really is in the payload;
    the gateway may or may not see this provenance. ``prior_write_applied`` is the
    hidden fact that an earlier write to the same target already took effect.
    """

    call_id: str
    run_id: str
    step: int
    tool: str
    target: str | None
    recipient: Recipient | None
    payload_sources: frozenset[str]
    payload_kb: float
    retry_after_unknown: bool
    prior_write_applied: bool
