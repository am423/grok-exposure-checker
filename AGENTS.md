# AGENTS.md — Grok Data Exposure Checker

> For any AI coding agent: Hermes, Cursor, Claude Code, Codex, Windsurf, Cline, etc.
> Zero dependencies. Python 3.8+. No network access needed.

## What This Does

Checks whether the Grok Build CLI (`grok`) uploaded user data to xAI's servers. Generates a styled HTML report with a visual traffic light, severity-coded findings, and actionable recommendations.

## Quick Start — One Command

```bash
python3 scripts/grok_exposure_check.py
```

The script generates `~/.grok/exposure-report.html`, auto-opens it in the default browser, and prints a brief summary to the terminal.

Flags: `--no-browser` (skip auto-open, useful when headless) and `-o/--output PATH` (write the report elsewhere).

## Output

- **HTML report**: `~/.grok/exposure-report.html` — styled, shareable
- **Terminal summary**: traffic-light status, critical file count, file path

If running headless (no browser), the HTML file is still generated. The agent can read and present the file path or serve it.

## When to Invoke

Users may ask:
- "Did Grok upload my data?"
- "Was my home directory exposed by Grok?"
- "Check my Grok installation for data exposure"
- "Am I affected by the Grok upload bug?"
- "Is my data safe with Grok Build?"

Any of these should trigger running the script.

## How to Invoke

1. Run `python3 scripts/grok_exposure_check.py` via your terminal/shell tool
2. Tell the user the report path: `~/.grok/exposure-report.html`
3. Summarize the traffic-light result in your response
4. If YELLOW or RED, walk through the Recommended Actions section

## Interpreting Results

### Traffic Light Status

| Status | Meaning | What to Tell the User |
|--------|---------|----------------------|
| GREEN | No upload events found | "You're clear. Always launch grok from project directories." |
| YELLOW | Upload attempted, outcome uncertain | "Possible exposure. Rotate these credentials as a precaution." |
| RED | Confirmed upload to xAI servers | "Confirmed data exposure. Rotate credentials immediately." |

### Sensitive File Severity

| Severity | Meaning | Urgency |
|----------|---------|---------|
| CRITICAL | Credentials allowing impersonation (SSH keys, .env, OAuth tokens) | Rotate now |
| HIGH | Sensitive data (API keys in config, package manager tokens) | Rotate soon |
| MEDIUM | Config that may contain secrets (.gitconfig, SSH authorized_keys) | Review |
| LOW | Minimal risk (known_hosts) | No action needed |

### Risk Assessment Logic

The tool classifies the overall risk as follows:

1. **No uploads at all** -> GREEN
2. **All uploads skipped** -> GREEN
3. **Confirmed upload + sensitive files in path** -> RED
4. **Confirmed upload, no sensitive files** -> RED
5. **Upload attempted (no confirmation) + sensitive files** -> YELLOW
6. **Upload attempted (no confirmation)** -> YELLOW

Key insight: A `repo_state.upload.start` event without a matching `.enqueued` event does NOT mean the upload failed. Grok fires uploads as background tasks and may complete without logging the confirmation. Treat any `upload.start` as a potential exposure.

## After Presenting Results

### GREEN — No Exposure
- Confirm they're safe
- Advise: always `cd` into a project directory before running `grok`
- Advise: never run `grok` from `~` or `/`
- Suggest periodic re-checks after Grok updates

### YELLOW — Possible Exposure
- Explain: Grok attempted to upload data but we can't confirm if it completed
- Recommend: treat as exposure and rotate CRITICAL credentials
- Help user set `coding_data_retention_opt_out = true` in `~/.grok/auth.json`
- Suggest deleting `~/.grok/upload_queue/` if it exists

### RED — Confirmed Exposure
- This is serious. Walk through each CRITICAL file found
- Help user rotate credentials:
  - SSH keys: `ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519`
  - API tokens: revoke and recreate on each provider's dashboard
  - Cloud credentials: rotate AWS/GCP/Azure keys
- Help user update Grok config to prevent recurrence
- Advise contacting xAI to request data deletion

## Understanding the Detection

The tool reads `~/.grok/logs/unified.jsonl` and tracks these event types:

- `repo_state.upload.start` — Grok began packaging a directory tree for upload. Contains the `repo_path` (what was targeted) and `phase` (before_codebase or after_codebase).
- `repo_state.upload.enqueued` — Upload confirmed. Contains the GCS path (where the data went) and size in bytes.
- `trace.upload.decision` — Per-session decision on whether telemetry/uploads are enabled. Controlled server-side by xAI.
- `repo_state.upload.skip` — Upload was explicitly skipped (safe).

### Path Scope Detection

The tool flags uploads where `repo_path` is:
- The user's home directory (CRITICAL — entire home tree was targeted)
- Root filesystem (CRITICAL)
- A parent of the home directory (CRITICAL)
- Not inside a git repo (ELEVATED — Grok walks the entire tree)

### Data Destinations

From binary analysis of the Grok CLI:
- **GCS bucket**: `grok-code-session-traces`
- **Upload proxy**: `cli-chat-proxy.grok.com`
- **Backend**: `code.grok.com`

## Cross-Platform Notes

| Platform | Grok Home | Path Separator |
|----------|-----------|----------------|
| Linux | `~/.grok` | `/` |
| macOS | `~/.grok` | `/` |
| Windows | `%USERPROFILE%\.grok` | `\` |

The script auto-detects the platform. On Windows, it may need to be run with `python` instead of `python3`.

## Privacy Guarantees

This tool:
- Reads ONLY Grok's own metadata files under `~/.grok/` (logs, `auth.json`, `version.json`) to reconstruct what happened
- For all other files (SSH keys, credentials, `.env`, etc.) it checks existence only and never reads their contents
- Does NOT transmit any data over the network
- Does NOT modify any files
- Generates the HTML report locally
- May surface the name/email from `auth.json` in the report; the footer flags this so users review before sharing

## Common Issues

1. **"Grok installation not found"** — Set `GROK_HOME` to the correct path
2. **"No log file found"** — Grok hasn't been used yet on this machine
3. **Report doesn't open in browser** — File is still at the printed path, open manually
4. **Script times out** — Should not happen. Known files are checked directly; the recursive scan for project-level secrets is bounded by depth and file count.

## Version

3.0 — July 2026
