"""Extract runs and tool calls from published AgentDojo traces (MIT, ETH Zurich).

AgentDojo labels a whole run: ``security`` is true when the injected attacker goal was
achieved. To look at single calls we mark a call whose arguments contain an identifier
(e-mail, IBAN, URL) that appears in the injected text but not in the user request.
This marker is a heuristic for EDA, not a reference label.
"""

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from agent_risk.catalog import Effect

SEND_FUNCTIONS: Final[frozenset[str]] = frozenset(
    {
        "send_money",
        "schedule_transaction",
        "send_email",
        "send_direct_message",
        "send_channel_message",
        "post_webpage",
        "share_file",
        "add_calendar_event_participants",
        "create_calendar_event",
        "invite_user_to_slack",
        "get_webpage",
    }
)
WRITE_PREFIXES: Final[tuple[str, ...]] = (
    "update_",
    "create_",
    "append_",
    "delete_",
    "reschedule_",
    "cancel_",
    "reserve_",
    "add_user_",
    "remove_user_",
)
PRIVILEGED_FUNCTIONS: Final[frozenset[str]] = frozenset(
    {
        "update_password",
        "update_user_info",
        "invite_user_to_slack",
        "add_user_to_channel",
        "remove_user_from_slack",
    }
)
IDENTIFIER = re.compile(
    r"[\w.+-]+@[\w-]+\.[\w.-]+|\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b|https?://\S+|www\.[\w./-]+"
)


def effect_of(function: str) -> Effect:
    """Map an AgentDojo function to the bench effect class (author's mapping).

    A call that delivers something outside the agent counts as a send: a request to an
    arbitrary URL can carry data in the address, and a new calendar event invites its
    participants.
    """
    if function in SEND_FUNCTIONS:
        return Effect.SEND
    if function.startswith(WRITE_PREFIXES):
        return Effect.WRITE
    return Effect.READ


@dataclass(frozen=True, slots=True)
class RunRow:
    """One AgentDojo trace."""

    run_key: str
    model: str
    suite: str
    user_task: str
    injection_task: str
    attack_type: str
    utility: bool
    security: bool
    n_calls: int
    n_send: int
    n_write: int
    duration_s: float
    error: bool


@dataclass(frozen=True, slots=True)
class DojoCallRow:
    """One tool call inside an AgentDojo trace."""

    run_key: str
    model: str
    suite: str
    attack_type: str
    step: int
    function: str
    effect: str
    privileged: bool
    n_args: int
    injection_seen_before: bool
    attacker_identifier_in_args: bool
    run_security: bool


def _text(value: object) -> str:
    """Message content as plain text; newer traces store a list of typed blocks."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = [
            str(block.get("content") or block.get("text") or "")
            for block in value
            if isinstance(block, dict)
        ]
        return "\n".join(parts)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


_ESCAPED_BREAK: Final = re.compile(r"\\\s*\n\s*\\?|\\[nrt]")


def _normalise(text: str) -> str:
    """Collapse whitespace: tool outputs re-wrap the injected text.

    Suites serialise tool results differently: ``repr`` leaves literal ``\\n`` and YAML
    continues a quoted line with a trailing backslash. Both are unfolded before the
    whitespace is collapsed, otherwise the injected text is not found where it was read.
    """
    return " ".join(_ESCAPED_BREAK.sub(" ", text).split())


def _identifiers(text: str) -> set[str]:
    return {m.rstrip(".,;:)'\"") for m in IDENTIFIER.findall(text)}


def parse_trace(path: Path, root: Path) -> tuple[RunRow, list[DojoCallRow]]:
    """Parse one trace file under ``root``/<model>/<suite>/<user_task>/<attack>/<file>."""
    data = json.loads(path.read_text(encoding="utf-8"))
    model = path.relative_to(root).parts[0]
    attack = data.get("attack_type") or "none"
    injections = data.get("injections") or {}
    injected_texts = [_text(v) for v in injections.values()] if isinstance(injections, dict) else []
    messages = data.get("messages") or []
    user_text = " ".join(
        _text(m.get("content")) for m in messages if m.get("role") in ("user", "system")
    )
    attacker_ids = set().union(*(_identifiers(t) for t in injected_texts)) - _identifiers(user_text)
    probes = [_normalise(t)[:60] for t in injected_texts if len(_normalise(t)) >= 20]
    run_key = str(path.relative_to(root).with_suffix(""))
    calls: list[DojoCallRow] = []
    seen_injection = False
    security = bool(data.get("security"))
    for message in messages:
        if message.get("role") == "tool":
            content = _normalise(_text(message.get("content")))
            seen_injection = seen_injection or any(p in content for p in probes)
        for call in message.get("tool_calls") or []:
            function = str(call.get("function"))
            args = call.get("args") or {}
            args_ids = _identifiers(_text(args))
            calls.append(
                DojoCallRow(
                    run_key=run_key,
                    model=model,
                    suite=str(data.get("suite_name")),
                    attack_type=attack,
                    step=len(calls),
                    function=function,
                    effect=effect_of(function).value,
                    privileged=function in PRIVILEGED_FUNCTIONS,
                    n_args=len(args) if isinstance(args, dict) else 0,
                    injection_seen_before=seen_injection,
                    attacker_identifier_in_args=bool(args_ids & attacker_ids),
                    run_security=security,
                )
            )
    run = RunRow(
        run_key=run_key,
        model=model,
        suite=str(data.get("suite_name")),
        user_task=str(data.get("user_task_id")),
        injection_task=str(data.get("injection_task_id") or "none"),
        attack_type=attack,
        utility=bool(data.get("utility")),
        security=security,
        n_calls=len(calls),
        n_send=sum(c.effect == Effect.SEND.value for c in calls),
        n_write=sum(c.effect == Effect.WRITE.value for c in calls),
        duration_s=round(float(data.get("duration") or 0.0), 2),
        error=bool(data.get("error")),
    )
    return run, calls


def iter_traces(root: Path) -> Iterator[Path]:
    """All trace files in a stable order."""
    yield from sorted(root.rglob("*.json"))
