"""Optional Claude explanations for findings the deterministic checks produced.

Design rules:
- The Python checks decide what a finding is. Claude only explains findings.
- Only an allow-listed set of fields from finding rows is sent; the full policy
  export never leaves the machine.
- Rule names and non-"any" address values are replaced with placeholders by
  default, and mapped back locally after the response returns.
- The API key comes from the ANTHROPIC_API_KEY environment variable and is
  never written to disk or logs by this module.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

DEFAULT_MODEL = "claude-sonnet-5-5"
MAX_FINDINGS = 25
MAX_TOKENS = 4000

# Finding types produced by app.py, with the check's own scope statement so the
# model explains the finding within what the check actually established.
FINDING_TYPES: dict[str, str] = {
    "broad_address": (
        "Enabled allow rule with an explicit 'any' source or destination address. "
        "Review filter only: zones, negation, rule order, applications, services "
        "and address-group contents were not assessed. Not proof of exposure."
    ),
    "cleartext_application": (
        "Enabled allow rule explicitly listing telnet, http or ftp in its "
        "application list. Application groups, dependencies and service ports "
        "were not assessed."
    ),
    "missing_profile": (
        "Enabled allow rule with a blank or 'none' security profile value in the "
        "export. Named profile or group contents were not inspected."
    ),
    "session_logging_disabled": (
        "Enabled rule with both 'Log at Session Start' and 'Log at Session End' "
        "explicitly set to off."
    ),
    "session_logging_unknown": (
        "Enabled rule whose session logging flags were blank or unrecognized, so "
        "logging state could not be determined."
    ),
    "missing_log_forwarding": (
        "Enabled rule with no log-forwarding profile in Log Setting. This does NOT "
        "mean session logging is disabled; it means logs may not be forwarded to "
        "external collectors from this rule. Profile contents and inheritance were "
        "not verified."
    ),
}

# Only these columns may be sent. UUID, descriptions, tags, owners and every
# other export column stay local.
ALLOWED_FIELDS = [
    "Rule Name",
    "Source Zone",
    "Destination Zone",
    "Source Address",
    "Destination Address",
    "Application",
    "Service",
    "Action",
    "Profile",
    "Log at Session Start",
    "Log at Session End",
    "Log Setting",
]

ADDRESS_FIELDS = {"Source Address", "Destination Address"}

SYSTEM_PROMPT = """You explain firewall policy review findings for a Palo Alto Networks \
security policy export. A deterministic Python tool has already decided each \
finding; you do not re-judge whether it is a finding.

For each finding:
- manager_summary: one or two plain-language sentences on why it matters to the business.
- engineer_note: concrete next review steps for a firewall engineer (what to check in \
the rule or Panorama, what change is typically considered). Do not give step-by-step \
CLI unless clearly safe and generic.
- verify_before_change: what must be confirmed before changing anything, given what the \
check did NOT assess.

Rules:
- Stay strictly within the check scope provided. Never claim confirmed exposure, \
compromise, or non-compliance.
- Placeholders such as RULE-1 or ADDR-1 are deliberate redactions; refer to them as given.
- Be concise. No marketing language.

Respond with ONLY a JSON array, one object per finding, each with keys: \
"id", "manager_summary", "engineer_note", "verify_before_change"."""


class ExplainerError(RuntimeError):
    """Raised for configuration or response problems the UI should display."""


def _clean(value: Any) -> str:
    if value is None:
        return ""
    try:
        import pandas as pd

        if pd.isna(value):
            return ""
    except (TypeError, ValueError, ImportError):
        pass
    return str(value).strip()


def build_payload(
    findings: dict[str, Any],
    redact: bool = True,
    max_findings: int = MAX_FINDINGS,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Turn finding DataFrames into the minimal records sent to Claude.

    findings maps a FINDING_TYPES key to a DataFrame of matching rows.
    Returns (payload, placeholder_map). placeholder_map maps placeholders back
    to real values and never leaves this machine.
    """
    unknown = sorted(set(findings) - set(FINDING_TYPES))
    if unknown:
        raise ExplainerError("Unknown finding type(s): " + ", ".join(unknown))

    payload: list[dict[str, Any]] = []
    placeholders: dict[str, str] = {}
    reverse: dict[tuple[str, str], str] = {}
    counters = {"RULE": 0, "ADDR": 0}

    def placeholder(kind: str, value: str) -> str:
        key = (kind, value)
        if key not in reverse:
            counters[kind] += 1
            token = f"{kind}-{counters[kind]}"
            reverse[key] = token
            placeholders[token] = value
        return reverse[key]

    for finding_type, frame in findings.items():
        if frame is None or len(frame) == 0:
            continue
        for _, row in frame.iterrows():
            if len(payload) >= max_findings:
                break
            fields: dict[str, str] = {}
            for column in ALLOWED_FIELDS:
                if column not in row.index:
                    continue
                value = _clean(row[column])
                if redact and column == "Rule Name" and value:
                    value = placeholder("RULE", value)
                elif redact and column in ADDRESS_FIELDS and value:
                    parts = [p.strip() for p in re.split(r"[;,\n]+", value) if p.strip()]
                    value = ";".join(
                        p if p.casefold() == "any" else placeholder("ADDR", p) for p in parts
                    )
                fields[column] = value
            payload.append(
                {
                    "id": f"F{len(payload) + 1}",
                    "finding_type": finding_type,
                    "check_scope": FINDING_TYPES[finding_type],
                    "rule": fields,
                }
            )
    return payload, placeholders


def restore_placeholders(text: str, placeholders: dict[str, str]) -> str:
    """Swap placeholders back to real values, longest token first."""
    for token in sorted(placeholders, key=len, reverse=True):
        text = re.sub(rf"\b{re.escape(token)}\b", placeholders[token], text)
    return text


def _parse_response(text: str, expected_ids: set[str]) -> list[dict[str, str]]:
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if not match:
        raise ExplainerError("Claude's response did not contain a JSON array.")
    try:
        items = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        raise ExplainerError(f"Claude's response was not valid JSON: {exc}") from exc
    required = {"id", "manager_summary", "engineer_note", "verify_before_change"}
    results = []
    for item in items:
        if not isinstance(item, dict) or not required.issubset(item):
            raise ExplainerError("Claude's response is missing required fields.")
        if item["id"] not in expected_ids:
            raise ExplainerError(f"Claude returned an unknown finding id: {item['id']}")
        results.append({key: str(item[key]) for key in required})
    missing = expected_ids - {r["id"] for r in results}
    if missing:
        raise ExplainerError("No explanation returned for: " + ", ".join(sorted(missing)))
    return results


def explain_findings(
    payload: list[dict[str, Any]],
    placeholders: dict[str, str] | None = None,
    client: Any = None,
    model: str | None = None,
) -> list[dict[str, str]]:
    """Send the payload to Claude and return explanations keyed by finding id.

    client is injectable for tests; otherwise an Anthropic client is created
    from the ANTHROPIC_API_KEY environment variable.
    """
    if not payload:
        return []
    if client is None:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise ExplainerError(
                "ANTHROPIC_API_KEY is not set. Set it in your shell before starting "
                "Streamlit to enable AI explanations."
            )
        import anthropic

        client = anthropic.Anthropic()
    model = model or os.environ.get("ANTHROPIC_MODEL", DEFAULT_MODEL)

    message = client.messages.create(
        model=model,
        max_tokens=MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": "Findings to explain:\n" + json.dumps(payload, indent=2),
            }
        ],
    )
    text = "".join(
        getattr(block, "text", "") for block in message.content if getattr(block, "type", "") == "text"
    )
    results = _parse_response(text, {item["id"] for item in payload})
    if placeholders:
        for result in results:
            for key in ("manager_summary", "engineer_note", "verify_before_change"):
                result[key] = restore_placeholders(result[key], placeholders)
    return results
