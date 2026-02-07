#!/usr/bin/env python3
"""
PII detection and redaction for Claude Code MCP tool calls.

Uses Claude Haiku to detect PII in tool inputs/outputs and redacts them
with typed tags like [EMAIL], [SSN], [PHONE_NUMBER], etc.

Called by Claude Code hooks (PreToolUse / PostToolUse).
Zero external dependencies — uses only Python stdlib.
"""

import json
import os
import sys
import urllib.request
import urllib.error
import argparse
import re

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-haiku-4-5-20251001"

DETECTION_PROMPT = """\
Analyze the following text for Personally Identifiable Information (PII).

Detect these PII types:
- EMAIL: Email addresses
- PHONE_NUMBER: Phone numbers (any format)
- SSN: Social Security Numbers
- CREDIT_CARD: Credit/debit card numbers
- NAME: Full person names (not company/product names)
- ADDRESS: Physical/mailing addresses
- DATE_OF_BIRTH: Dates of birth
- IP_ADDRESS: IP addresses (v4 and v6)
- PASSPORT: Passport numbers
- DRIVERS_LICENSE: Driver's license numbers
- BANK_ACCOUNT: Bank account/routing numbers

For each PII found, return its exact text as it appears and its type.

Return ONLY a JSON array. No other text. Examples:
- Found PII: [{"text": "john@example.com", "type": "EMAIL"}, {"text": "555-123-4567", "type": "PHONE_NUMBER"}]
- No PII: []

Text to analyze:
<content>
{content}
</content>"""

MAX_CONTENT_LENGTH = 50000  # Truncate very large content for API call


def get_api_key():
    """Get Anthropic API key from environment."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    return key


def call_haiku(content, api_key):
    """Call Claude Haiku to detect PII in content. Returns list of {text, type}."""
    if not content or not content.strip():
        return []

    truncated = content[:MAX_CONTENT_LENGTH]
    prompt = DETECTION_PROMPT.replace("{content}", truncated)

    payload = json.dumps({
        "model": MODEL,
        "max_tokens": 4096,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")

    req = urllib.request.Request(
        ANTHROPIC_API_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )

    resp = urllib.request.urlopen(req, timeout=25)
    body = json.loads(resp.read().decode("utf-8"))

    text = body["content"][0]["text"].strip()

    # Extract JSON array from response (handle markdown fences)
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if not match:
        return []

    return json.loads(match.group(0))


def redact(text, pii_items):
    """Replace each PII occurrence with its typed tag."""
    redacted = text
    # Sort by length descending to avoid partial replacements
    for item in sorted(pii_items, key=lambda x: len(x["text"]), reverse=True):
        tag = f'[{item["type"]}]'
        redacted = redacted.replace(item["text"], tag)
    return redacted


def flatten_text(obj):
    """Recursively extract all string values from a JSON object."""
    parts = []
    if isinstance(obj, str):
        parts.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            parts.extend(flatten_text(v))
    elif isinstance(obj, list):
        for v in obj:
            parts.extend(flatten_text(v))
    return parts


def redact_obj(obj, pii_items):
    """Recursively redact PII from all string values in a JSON object."""
    if not pii_items:
        return obj
    if isinstance(obj, str):
        return redact(obj, pii_items)
    elif isinstance(obj, dict):
        return {k: redact_obj(v, pii_items) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [redact_obj(v, pii_items) for v in obj]
    return obj


def handle_pre_tool_use(hook_input, api_key):
    """Detect and redact PII from tool input before execution."""
    tool_input = hook_input.get("tool_input", {})

    # Flatten all string content for PII scanning
    all_text = "\n".join(flatten_text(tool_input))
    if not all_text.strip():
        # No text content to scan
        return json.dumps({})

    pii_items = call_haiku(all_text, api_key)
    if not pii_items:
        # No PII found — allow as-is
        return json.dumps({})

    # Redact PII from tool input
    redacted_input = redact_obj(tool_input, pii_items)
    types_found = sorted(set(item["type"] for item in pii_items))

    return json.dumps({
        "hookSpecificOutput": {
            "permissionDecision": "allow",
            "updatedInput": redacted_input,
        },
        "systemMessage": f"PII redacted from tool input. Types found: {', '.join(types_found)}",
    })


def handle_post_tool_use(hook_input, api_key):
    """Detect and redact PII from tool output after execution."""
    tool_result = hook_input.get("tool_result", "")

    # tool_result can be a string or structured object
    all_text = "\n".join(flatten_text(tool_result))
    if not all_text.strip():
        return json.dumps({})

    pii_items = call_haiku(all_text, api_key)
    if not pii_items:
        return json.dumps({})

    redacted_result = redact_obj(tool_result, pii_items)
    types_found = sorted(set(item["type"] for item in pii_items))

    # For PostToolUse, provide redacted content via systemMessage
    if isinstance(redacted_result, str):
        redacted_display = redacted_result
    else:
        redacted_display = json.dumps(redacted_result, indent=2)

    return json.dumps({
        "systemMessage": (
            f"PII detected in tool output ({', '.join(types_found)}). "
            f"Use this redacted version instead:\n\n{redacted_display}"
        ),
    })


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hook", required=True, choices=["pre", "post"])
    args = parser.parse_args()

    # Read hook input from stdin
    try:
        hook_input = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        # Can't parse input — fail open
        sys.exit(0)

    # Check for API key
    api_key = get_api_key()
    if not api_key:
        # No API key — fail open with a warning
        print(json.dumps({
            "systemMessage": "guardrails-pii: ANTHROPIC_API_KEY not set. PII redaction skipped.",
        }))
        sys.exit(0)

    try:
        if args.hook == "pre":
            result = handle_pre_tool_use(hook_input, api_key)
        else:
            result = handle_post_tool_use(hook_input, api_key)

        print(result)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, KeyError) as e:
        # API call failed — fail open
        print(json.dumps({
            "systemMessage": f"guardrails-pii: PII detection unavailable ({type(e).__name__}). Tool call proceeded without redaction.",
        }))
        sys.exit(0)


if __name__ == "__main__":
    main()
