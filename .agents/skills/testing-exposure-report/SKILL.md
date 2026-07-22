---
name: testing-exposure-report
description: Test the Grok Data Exposure Checker end-to-end by running the CLI against synthetic ~/.grok fixtures and verifying the generated HTML report in the browser. Use when verifying changes to scripts/grok_exposure_check.py or its report output.
---

# Testing the Grok Data Exposure Checker

The tool is a dependency-free Python CLI (`scripts/grok_exposure_check.py`) that reads a
Grok home directory's logs and writes an HTML report. There is no server — test by
pointing `GROK_HOME` at a synthetic fixture and opening the generated HTML.

## Devin Secrets Needed
None. The tool is stdlib-only, offline, and needs no credentials.

## Fast path
```bash
GROK_HOME=/path/to/fixture python3 scripts/grok_exposure_check.py \
  --no-browser -o /home/ubuntu/screenshots/report.html
python3 -m unittest discover -s tests   # 22 unit tests, ~0.01s
```
Then open `file:///home/ubuntu/screenshots/report.html` in Chrome to inspect visually.
Write reports to `/home/ubuntu/screenshots/` (persistent) rather than `/tmp` so screenshots survive.

## Building a fixture
A fixture is a directory containing `logs/unified.jsonl` (required) and optionally
`auth.json` and `version.json`. Log lines are JSON objects with `msg`, `sid`, `ts`, `ctx`.
Key event types: `repo_state.upload.start`, `repo_state.upload.enqueued` (confirms),
`repo_state.upload.skip`, `trace.upload.decision`.

- **RED (confirmed exposure):** a `start` + matching `enqueued`, plus a sensitive file
  inside the `repo_path`. To exercise the deep-scan, put an `.env` several levels deep
  *inside* the confirmed upload's `repo_path` (the scan walks `repo_path`, NOT home,
  unless home is inside the uploaded tree).
- **GREEN:** a `start` + `skip` (all-skipped) or no uploads at all.
- **Adversarial coverage in one RED fixture:** version `0.2.100` (checks numeric compare,
  not lexicographic), an `enqueued` whose `gcs_path` lacks `before_/after_codebase`
  (checks sid-based matching → single card), a second `start` whose `repo_path` no longer
  exists (checks UNKNOWN "scope unverifiable", not false ELEVATED), non-string `ts`
  (checks no crash), and `auth.json` with name/email (checks PII footer warning).

## Gotchas / things that might break
- **Recursive-scan noise:** when `repo_path` is the home dir (or a parent), the walk can
  surface many language-runtime test fixtures (e.g. pyenv/CPython `*.pem` files). The
  skip-list (`WALK_SKIP_DIRS`) should exclude `.pyenv`, `.cache`, `site-packages`, etc.
  If a report shows dozens of `*.pem` under `.pyenv`/`site-packages`, the skip-list needs
  extending. Prefer a `repo_path` pointing at a small dedicated fixture tree so the
  sensitive-files list stays focused on your planted secret.
- A `repo_path` that *exists* and lacks `.git` is correctly **ELEVATED**; only a
  *missing* path is **UNKNOWN**. Use a deleted/nonexistent path to prove UNKNOWN.
- Report files are written `0600`; that's intentional (owner-only).

## Recording
Record the browser viewing the RED report (traffic light, version badge, upload cards,
sensitive files, PII footer) then the GREEN report. Annotate with test_start/assertion.
Use `wmctrl -r :ACTIVE: -b add,maximized_vert,maximized_horz` to maximize Chrome first.

## Lint
`python3 -m pyflakes scripts tests` and `python3 -m flake8 --select=E9,F` (repo has
pre-existing long-line/f-string style warnings unrelated to correctness). No CI configured.
