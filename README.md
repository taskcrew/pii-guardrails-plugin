# guardrails-pii

A Claude Code plugin that detects and redacts Personally Identifiable Information (PII) from MCP tool calls using Claude Haiku.

## How it works

Two hooks intercept every MCP tool call:

1. **PreToolUse** — Scans tool **inputs** before the tool executes. Detected PIIs are redacted in-place, so the MCP server never sees the original data.
2. **PostToolUse** — Scans tool **outputs** after the tool returns. Detected PIIs are redacted before Claude processes the result.

PII detection is powered by Claude Haiku for fast, accurate, context-aware identification. Redacted values are replaced with typed tags:

```
john@acme.com    →  [EMAIL]
555-123-4567     →  [PHONE_NUMBER]
123-45-6789      →  [SSN]
John Smith       →  [NAME]
```

### Supported PII types

`EMAIL`, `PHONE_NUMBER`, `SSN`, `CREDIT_CARD`, `NAME`, `ADDRESS`, `DATE_OF_BIRTH`, `IP_ADDRESS`, `PASSPORT`, `DRIVERS_LICENSE`, `BANK_ACCOUNT`

## Prerequisites

- Python 3.7+
- An Anthropic API key with access to Claude Haiku

## Installation

### As a Claude Code plugin

```bash
# Clone the repository
git clone https://github.com/taskcrew/pii-guardrails-plugin.git

# Use as a local plugin
claude --plugin-dir /path/to/pii-guardrails-plugin
```

### Set your API key

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

## Scope

The plugin only intercepts **MCP tool calls** (tools matching `mcp__*`). Built-in Claude Code tools (Read, Write, Bash, etc.) are not affected.

## Failure mode

The plugin **fails open** — if the API key is missing, the Haiku call fails, or any error occurs, the tool call proceeds without redaction. A system message notifies Claude that redaction was skipped.

## Architecture

```
guardrails-plugin/
├── .claude-plugin/
│   └── plugin.json           # Plugin manifest
├── hooks/
│   ├── hooks.json            # PreToolUse + PostToolUse hook config
│   └── scripts/
│       └── pii-redact.py     # Haiku-powered PII detection & redaction
└── README.md
```

## License

MIT
