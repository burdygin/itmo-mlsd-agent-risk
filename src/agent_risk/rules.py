"""Baselines B0 and B1 from the design document, computed on gateway features only."""

from agent_risk.catalog import Effect, Scope
from agent_risk.gateway import UNKNOWN_CLASS, CallFeatures, Match


def b0(_: CallFeatures) -> bool:
    """B0: every call that passed IAM is low risk."""
    return False


def b1_reasons(f: CallFeatures) -> tuple[str, ...]:
    """Fixed rules of B1; a non-empty result routes the call to confirmation."""
    reasons: list[str] = []
    is_send = f.effect == Effect.SEND.value
    if not f.effect_in_task:
        reasons.append("effect_outside_task")
    if Match.NO.value in (f.object_matches_task, f.recipient_matches_task):
        reasons.append("argument_outside_manifest")
    if is_send and f.payload_class_allowed == Match.NO.value:
        reasons.append("payload_class_outside_task")
    if (
        is_send
        and f.destination_scope == Scope.EXTERNAL.value
        and f.payload_class == UNKNOWN_CLASS
        and f.sensitive_read_before
    ):
        reasons.append("sensitive_read_before_external_send")
    if f.effect == Effect.WRITE.value and f.retry_after_unknown:
        reasons.append("write_retry_after_unknown_outcome")
    return tuple(reasons)


def b1(f: CallFeatures) -> bool:
    """B1 decision: ``True`` means high risk."""
    return bool(b1_reasons(f))


def b1_plus_reasons(f: CallFeatures) -> tuple[str, ...]:
    """B1+: B1 and the EDA signal of a write after an ambiguous lookup.

    With an incomplete manifest the gateway cannot tell object A from object B of the
    same class; EDA showed that wrong-object writes follow ambiguous lookups more often.
    """
    reasons = list(b1_reasons(f))
    if (
        f.effect == Effect.WRITE.value
        and f.object_matches_task == Match.UNKNOWN.value
        and f.ambiguous_lookup
    ):
        reasons.append("write_after_ambiguous_lookup")
    return tuple(reasons)


def b1_plus(f: CallFeatures) -> bool:
    """B1+ decision: ``True`` means high risk."""
    return bool(b1_plus_reasons(f))
