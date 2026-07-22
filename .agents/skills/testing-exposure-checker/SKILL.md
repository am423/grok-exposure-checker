---
name: testing-exposure-checker
description: Test the Grok Data Exposure Checker (scripts/grok_exposure_check.py) end-to-end. Use when verifying changes to the checker's log parsing, risk assessment, sensitive-file scan, error handling, or HTML report.
---

# Testing the Grok Data Exposure Checker

Single zero-dependency Python CLI (`scripts/grok_exposure_check.py`, Python 3.8+). No secrets, no network.
It reads `$GROK_HOME/logs/unified.jsonl`, assesses risk (GREEN/YELLOW/RED), scans upload `repo_path`s for
sensitive files, and writes `$GROK_HOME/exposure-report.html`.

## Devin Secrets Needed
None.

## How to drive it
Point `GROK_HOME` at a throwaway fixture dir — never your real `~/.grok`:
```bash
GROK_HOME=/tmp/fixture python3 scripts/grok_exposure_check.py
```
Report is written to `$GROK_HOME/exposure-report.html`; open with `file://` in Chrome to verify the UI.

## Building fixtures
- Log lives at `$GROK_HOME/logs/unified.jsonl`, one JSON object per line.
- Event `msg` values that matter: `repo_state.upload.start` (needs `ctx.repo_path`, `ctx.phase`),
  `repo_state.upload.enqueued` (`ctx.gcs_path`, `ctx.size_bytes` → status "confirmed" → RED),
  `repo_state.upload.skip` (`ctx.reason` → GREEN), `trace.upload.decision` (`ctx.uploads_enabled`).
- To trigger CRITICAL sensitive-file findings, create the referenced `repo_path` dir and drop e.g.
  `.ssh/id_rsa` or `.env` inside it (the scanner checks real file existence under `repo_path`).
- To trigger error paths: `chmod 000` the log (read error) or `auth.json` (side-file error); add
  non-JSON lines to the log (malformed-line warning).

## Key behaviors to assert (esp. for error-handling changes)
- Unreadable log → process exits **non-zero** with an ERROR; must NOT print GREEN (a false all-clear
  is the dangerous regression to guard against for a security tool).
- Non-fatal problems (malformed lines, unreadable auth.json/version.json, unscannable dirs) surface as
  warnings: stderr `WARNING:`, a terminal `N warning(s)` count, and a **"Scan Warnings" section** in the HTML.
- Clean/skip-only log stays GREEN with no warnings.

## Testing tips
- T1 (unreadable log) and regression (clean) are terminal-only — capture exit codes as text evidence.
- The report is the UI: record the browser only for the report-rendering cases (RED + Scan Warnings).
- Verify report content quickly without a browser via `grep` on the generated HTML
  (e.g. `grep 'light-label' report.html`, `grep 'Scan Warnings' report.html`).
