"""Shared vocabulary of the test bench: effects, data classes, scopes and tools.

Both the gateway view (features) and the consequence oracle (labels) import these
types, so one concept has one definition. Nothing here knows about labels.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Final


class Effect(StrEnum):
    """Side effect of a tool operation."""

    READ = "read"
    WRITE = "write"
    SEND = "send"


class DataClass(StrEnum):
    """Sensitivity class of a stored object or of data inside a payload."""

    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"


DATA_CLASS_RANK: Final[dict[DataClass, int]] = {
    DataClass.PUBLIC: 0,
    DataClass.INTERNAL: 1,
    DataClass.SENSITIVE: 2,
}


class Scope(StrEnum):
    """Where data goes after a call."""

    NONE = "none"
    INTERNAL = "internal"
    EXTERNAL = "external"


class TaskKind(StrEnum):
    """Category of the user assignment recorded in the verified task manifest."""

    LOCAL_SUMMARY = "local_summary"
    SEND_REPORT = "send_report"
    UPDATE_RECORD = "update_record"
    TRIAGE_INBOX = "triage_inbox"
    SHARE_INTERNAL = "share_internal"


class ContextLevel(StrEnum):
    """How much of the manifest and data provenance the gateway can see."""

    FULL = "full"
    CLASS_ONLY = "class_only"
    NO_PROVENANCE = "no_provenance"
    MINIMAL = "minimal"


@dataclass(frozen=True, slots=True)
class Tool:
    """Tool catalog entry: the gateway knows the effect and the possible scopes."""

    name: str
    effect: Effect
    scopes: tuple[Scope, ...]


TOOLS: Final[dict[str, Tool]] = {
    tool.name: tool
    for tool in (
        Tool("read_document", Effect.READ, (Scope.NONE,)),
        Tool("search_documents", Effect.READ, (Scope.NONE,)),
        Tool("read_email", Effect.READ, (Scope.NONE,)),
        Tool("list_records", Effect.READ, (Scope.NONE,)),
        Tool("update_record", Effect.WRITE, (Scope.NONE,)),
        Tool("delete_record", Effect.WRITE, (Scope.NONE,)),
        Tool("create_document", Effect.WRITE, (Scope.NONE,)),
        Tool("send_email", Effect.SEND, (Scope.INTERNAL, Scope.EXTERNAL)),
        Tool("post_message", Effect.SEND, (Scope.INTERNAL,)),
        Tool("upload_external", Effect.SEND, (Scope.EXTERNAL,)),
        Tool("share_document", Effect.SEND, (Scope.INTERNAL, Scope.EXTERNAL)),
    )
}

READ_TOOLS: Final[tuple[str, ...]] = tuple(
    t.name for t in TOOLS.values() if t.effect is Effect.READ
)
