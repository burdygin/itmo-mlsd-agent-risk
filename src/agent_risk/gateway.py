"""Gateway view: features available before execution at the moment of scoring.

Features depend on the context level: an incomplete manifest gives only the class of
allowed objects and the scope of allowed recipients, and a missing provenance tag
hides the class of data inside the payload. Labels, seeds, family IDs and the hidden
facts of :class:`agent_risk.world.ProposedCall` never become features.
"""

from dataclasses import dataclass
from enum import StrEnum

from agent_risk.catalog import (
    DATA_CLASS_RANK,
    TOOLS,
    ContextLevel,
    DataClass,
    Effect,
    Scope,
)
from agent_risk.world import ProposedCall, StoredObject, TaskManifest


class Match(StrEnum):
    """Whether an argument matches the manifest, as far as the gateway can tell."""

    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"
    NA = "na"


UNKNOWN_CLASS = "unknown"
NOT_APPLICABLE = "na"


@dataclass(frozen=True, slots=True)
class History:
    """Gateway journal of the run before the current call."""

    n_prev_calls: int = 0
    max_read_class: DataClass | None = None
    external_send_before: bool = False
    untrusted_input_before: bool = False
    last_recipient: str | None = None
    ambiguous_lookup: bool = False


@dataclass(frozen=True, slots=True)
class CallFeatures:
    """One row of the ``calls`` table: identifiers plus features at ``t_score``."""

    call_id: str
    run_id: str
    task_kind: str
    context_level: str
    tool: str
    effect: str
    effect_in_task: bool
    target_class: str
    destination_scope: str
    payload_kb: float
    object_matches_task: str
    recipient_matches_task: str
    payload_class: str
    payload_class_allowed: str
    n_prev_calls: int
    max_read_class_before: str
    sensitive_read_before: bool
    external_send_before: bool
    untrusted_input_before: bool
    recipient_changed: bool
    retry_after_unknown: bool
    ambiguous_lookup: bool


def _exact_manifest(level: ContextLevel) -> bool:
    return level in (ContextLevel.FULL, ContextLevel.NO_PROVENANCE)


def _provenance_visible(level: ContextLevel) -> bool:
    return level in (ContextLevel.FULL, ContextLevel.CLASS_ONLY)


def _object_match(
    manifest: TaskManifest,
    objects: dict[str, StoredObject],
    call: ProposedCall,
    level: ContextLevel,
) -> Match:
    tool = TOOLS[call.tool]
    if tool.effect is not Effect.WRITE or call.target is None:
        return Match.NA
    if Effect.WRITE not in manifest.allowed_effects:
        return Match.NO
    if _exact_manifest(level):
        return Match.YES if call.target in manifest.allowed_write_objects else Match.NO
    target = objects.get(call.target)
    if target is None or manifest.write_class is None:
        return Match.UNKNOWN
    return Match.UNKNOWN if target.data_class is manifest.write_class else Match.NO


def _recipient_match(manifest: TaskManifest, call: ProposedCall, level: ContextLevel) -> Match:
    if TOOLS[call.tool].effect is not Effect.SEND or call.recipient is None:
        return Match.NA
    if Effect.SEND not in manifest.allowed_effects:
        return Match.NO
    if _exact_manifest(level):
        return Match.YES if call.recipient.address in manifest.allowed_recipients else Match.NO
    if manifest.recipient_scope is None:
        return Match.UNKNOWN
    return Match.UNKNOWN if call.recipient.scope is manifest.recipient_scope else Match.NO


def _payload_class(
    objects: dict[str, StoredObject], call: ProposedCall, level: ContextLevel
) -> DataClass | None:
    """Highest class inside the payload, or ``None`` when the gateway cannot see it.

    A source missing from the object store has no known class, so the whole payload is
    unknown: dropping it would report a lower class than the one actually sent.
    """
    if not _provenance_visible(level):
        return None
    if any(s not in objects for s in call.payload_sources):
        return None
    classes = [objects[s].data_class for s in call.payload_sources]
    if not classes:
        return DataClass.PUBLIC
    return max(classes, key=DATA_CLASS_RANK.__getitem__)


def extract_features(
    manifest: TaskManifest,
    objects: dict[str, StoredObject],
    call: ProposedCall,
    history: History,
    level: ContextLevel,
) -> CallFeatures:
    """Build the gateway feature row for ``call``; only pre-execution facts are used."""
    tool = TOOLS[call.tool]
    is_send = tool.effect is Effect.SEND
    target = objects.get(call.target) if call.target is not None else None
    payload_class = _payload_class(objects, call, level) if is_send else None
    if not is_send:
        payload_label, payload_allowed = NOT_APPLICABLE, Match.NA
    elif payload_class is None:
        payload_label, payload_allowed = UNKNOWN_CLASS, Match.UNKNOWN
    else:
        allowed = payload_class in manifest.allowed_send_classes
        payload_label, payload_allowed = payload_class.value, Match.YES if allowed else Match.NO
    recipient = call.recipient
    return CallFeatures(
        call_id=call.call_id,
        run_id=call.run_id,
        task_kind=manifest.kind.value,
        context_level=level.value,
        tool=tool.name,
        effect=tool.effect.value,
        effect_in_task=tool.effect in manifest.allowed_effects,
        target_class=target.data_class.value if target is not None else NOT_APPLICABLE,
        destination_scope=recipient.scope.value if recipient is not None else Scope.NONE.value,
        payload_kb=round(call.payload_kb, 1),
        object_matches_task=_object_match(manifest, objects, call, level).value,
        recipient_matches_task=_recipient_match(manifest, call, level).value,
        payload_class=payload_label,
        payload_class_allowed=payload_allowed.value,
        n_prev_calls=history.n_prev_calls,
        max_read_class_before=(
            history.max_read_class.value if history.max_read_class is not None else "none"
        ),
        sensitive_read_before=history.max_read_class is DataClass.SENSITIVE,
        external_send_before=history.external_send_before,
        untrusted_input_before=history.untrusted_input_before,
        recipient_changed=(
            recipient is not None
            and history.last_recipient is not None
            and recipient.address != history.last_recipient
        ),
        retry_after_unknown=call.retry_after_unknown,
        ambiguous_lookup=history.ambiguous_lookup,
    )
