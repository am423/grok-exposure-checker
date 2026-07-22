#!/usr/bin/env python3
"""
Grok Data Exposure Checker v3
=============================
Standalone tool — works with any AI agent (Hermes, Cursor, Claude, Codex, etc.)
or directly from the terminal. No dependencies beyond Python 3.8+.

Generates a styled HTML report with visual traffic-light, severity-coded
findings, and actionable recommendations.

Output: ~/.grok/exposure-report.html (and terminal summary)
"""

import json
import os
import sys
import html
import webbrowser
from datetime import datetime
from pathlib import Path


# ── Warning collection ───────────────────────────────────────────────────────
# Non-fatal problems (unscannable directories, unreadable side files) must not
# vanish silently — for a security tool a swallowed error can hide real
# exposure. Collect them here so they are printed to stderr and surfaced in
# the report instead of being dropped.

WARNINGS = []


def warn(message):
    WARNINGS.append(message)
    print(f"  WARNING: {message}", file=sys.stderr)


# ── Sensitive File Definitions ───────────────────────────────────────────────
# Format: (relative_path, description, severity)
# Severity: CRITICAL = credentials that allow impersonation
#           HIGH = sensitive data worth protecting
#           MEDIUM = config that may contain secrets
#           LOW = minimal risk metadata

SENSITIVE_FILES = [
    # SSH
    (".ssh/id_rsa", "SSH private key (RSA)", "CRITICAL"),
    (".ssh/id_ecdsa", "SSH private key (ECDSA)", "CRITICAL"),
    (".ssh/id_ed25519", "SSH private key (Ed25519)", "CRITICAL"),
    (".ssh/id_dsa", "SSH private key (DSA)", "CRITICAL"),
    (".ssh/authorized_keys", "SSH authorized keys", "MEDIUM"),
    (".ssh/known_hosts", "SSH known hosts", "LOW"),
    (".ssh/config", "SSH config", "MEDIUM"),

    # Cloud credentials
    (".aws/credentials", "AWS credentials", "CRITICAL"),
    (".aws/config", "AWS config", "HIGH"),
    (".config/gcloud/application_default_credentials.json", "GCloud default creds", "CRITICAL"),
    (".config/gcloud/credentials.db", "GCloud credentials DB", "CRITICAL"),
    (".azure/azure-cli-credentials.json", "Azure CLI credentials", "CRITICAL"),
    (".kube/config", "Kubernetes cluster credentials", "CRITICAL"),

    # Environment / secrets
    (".env", "Environment file (likely secrets)", "CRITICAL"),
    (".env.local", "Environment file (local)", "CRITICAL"),
    (".env.production", "Environment file (production)", "CRITICAL"),
    (".env.staging", "Environment file (staging)", "HIGH"),

    # Package manager tokens
    (".npmrc", "npm auth token", "HIGH"),
    (".pypirc", "PyPI auth token", "HIGH"),
    (".netrc", "Netrc credentials", "CRITICAL"),

    # Docker
    (".docker/config.json", "Docker registry auth", "CRITICAL"),
    (".dockercfg", "Docker legacy auth", "CRITICAL"),

    # Git
    (".git-credentials", "Git stored credentials", "CRITICAL"),
    (".gitconfig", "Git config (check for tokens)", "MEDIUM"),

    # Grok itself
    (".grok/auth.json", "Grok auth tokens (OAuth, refresh tokens)", "CRITICAL"),
    (".grok/config.toml", "Grok config (may contain API keys)", "HIGH"),

    # Hermes
    (".hermes/config.yaml", "Hermes config", "HIGH"),
    (".hermes/.env", "Hermes environment file", "CRITICAL"),

    # Crypto
    (".bitcoin/wallet.dat", "Bitcoin wallet", "CRITICAL"),
    (".ethereum/keystore", "Ethereum keystore", "CRITICAL"),

    # GPG
    (".gnupg/secring.gpg", "GPG secret keyring", "CRITICAL"),
    (".gnupg/private-keys-v1.d", "GPG private keys directory", "CRITICAL"),

    # Common project-level secrets
    ("secrets.json", "Secrets file", "CRITICAL"),
    ("credentials.json", "Credentials file", "CRITICAL"),
    ("service-account-key.json", "GCP service account key", "CRITICAL"),
]

SENSITIVE_GLOBS = [
    ("*.pem", "PEM certificate/key file", "HIGH"),
    ("*.key", "Private key file", "HIGH"),
    ("*.env", "Environment file", "CRITICAL"),
]

# Directory prefixes searched for each sensitive glob (self, one level down, dotdirs)
GLOB_PREFIXES = ["", "*/", ".*/"]

# ── Severity Model ───────────────────────────────────────────────────────────
# Single source of truth for severity ordering and display colors.
SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_ORDER = {sev: i for i, sev in enumerate(SEVERITY_LEVELS)}
SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f59e0b",
    "MEDIUM": "#3b82f6",
    "LOW": "#6b7280",
}
SEVERITY_FALLBACK_COLOR = "#6b7280"


def get_grok_home():
    if os.environ.get("GROK_HOME"):
        return Path(os.environ["GROK_HOME"])
    return Path.home() / ".grok"


def check_sensitive_files(base_path):
    results = []
    base = Path(base_path)
    if not base.exists() or not base.is_dir():
        return results

    for rel_path, description, severity in SENSITIVE_FILES:
        candidate = base / rel_path
        if candidate.exists():
            results.append((rel_path, description, str(candidate), severity))

    for pattern, description, severity in SENSITIVE_GLOBS:
        try:
            for prefix in GLOB_PREFIXES:
                for found in list(base.glob(f"{prefix}{pattern}"))[:5]:
                    results.append((pattern, description, str(found), severity))
        except (PermissionError, OSError) as e:
            warn(f"Could not scan {base} for pattern '{pattern}': {e}")

    # Check SSH id_* keys
    home = Path.home()
    if base.resolve() == home.resolve():
        ssh_dir = base / ".ssh"
        if ssh_dir.is_dir():
            try:
                for key_file in ssh_dir.iterdir():
                    if key_file.is_file() and key_file.name.startswith("id_"):
                        results.append((f".ssh/{key_file.name}", f"SSH key ({key_file.name})", str(key_file), "CRITICAL"))
            except (PermissionError, OSError) as e:
                warn(f"Could not list SSH directory {ssh_dir}: {e}")

    seen = set()
    deduped = []
    for item in results:
        path = item[2]
        if path not in seen:
            seen.add(path)
            deduped.append(item)
    return deduped


def parse_logs(log_file):
    """Parse the unified JSONL log into a list of entries.

    Raises OSError if the log exists but cannot be read. Callers MUST treat an
    unreadable log as an error rather than as "no activity": silently returning
    an empty list would make an unreadable log indistinguishable from a clean
    one and yield a false GREEN result.
    """
    entries = []
    if not log_file.exists():
        return entries
    malformed = 0
    with open(log_file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                malformed += 1
    if malformed:
        warn(f"{malformed} malformed log line(s) skipped in {log_file}")
    return entries


def analyze_uploads(entries):
    uploads = []
    telemetry = []

    for entry in entries:
        msg = entry.get("msg", "")
        ctx = entry.get("ctx", {})
        ts = entry.get("ts", "")
        sid = entry.get("sid", "unknown")

        if "repo_state.upload.start" in msg:
            uploads.append({
                "timestamp": ts, "session_id": sid,
                "phase": ctx.get("phase", "unknown"),
                "repo_path": ctx.get("repo_path", "unknown"),
                "max_file_bytes": ctx.get("max_file_bytes"),
                "status": "started", "gcs_path": None, "size_bytes": None,
            })

        elif "repo_state.upload.enqueued" in msg:
            gcs = ctx.get("gcs_path", "")
            phase = "before_codebase" if "before_codebase" in gcs else \
                    "after_codebase" if "after_codebase" in gcs else "unknown"
            for u in reversed(uploads):
                if u["session_id"] == sid and u["phase"] == phase and u["status"] == "started":
                    u["status"] = "confirmed"
                    u["gcs_path"] = gcs
                    u["size_bytes"] = ctx.get("size_bytes")
                    break
            else:
                uploads.append({
                    "timestamp": ts, "session_id": sid, "phase": phase,
                    "repo_path": "unknown", "max_file_bytes": None,
                    "status": "confirmed", "gcs_path": gcs, "size_bytes": ctx.get("size_bytes"),
                })

        elif "repo_state.upload.skip" in msg:
            reason = ctx.get("reason", "unknown")
            for u in reversed(uploads):
                if u["session_id"] == sid and u["status"] == "started":
                    u["status"] = "skipped"
                    u["gcs_path"] = f"skipped: {reason}"
                    break

        elif "trace.upload.decision" in msg:
            telemetry.append({
                "timestamp": ts, "session_id": sid,
                "uploads_enabled": ctx.get("uploads_enabled"),
                "upload_reason": ctx.get("upload_reason"),
            })

    return uploads, telemetry


def assess_path_scope(repo_path):
    path_str = str(repo_path).lower().replace("\\", "/")
    home_str = str(Path.home()).lower().replace("\\", "/")

    if path_str.rstrip("/") == home_str.rstrip("/"):
        return "CRITICAL", "ENTIRE HOME DIRECTORY targeted"
    if path_str in ("/", "c:/", "c:\\", ""):
        return "CRITICAL", "ROOT FILESYSTEM targeted"
    if home_str.startswith(path_str.rstrip("/")) and path_str.count("/") <= 4:
        return "CRITICAL", "Parent of home directory targeted"
    if not Path(repo_path).joinpath(".git").exists():
        return "ELEVATED", "NOT a git repo — Grok walks entire tree"
    return "NORMAL", None


def assess_risk(uploads, sensitive_files):
    if not uploads:
        return "GREEN", "No upload events found"
    has_confirmed = any(u["status"] == "confirmed" for u in uploads)
    has_started = any(u["status"] == "started" for u in uploads)
    has_sensitive = len(sensitive_files) > 0
    all_skipped = all(u["status"] == "skipped" for u in uploads)

    if all_skipped:
        return "GREEN", "All uploads were explicitly skipped"
    if has_confirmed and has_sensitive:
        return "RED", "CONFIRMED upload with sensitive files in path"
    if has_confirmed:
        return "RED", "CONFIRMED data upload to xAI servers"
    if has_started and has_sensitive:
        return "YELLOW", "Upload attempted, sensitive files in path"
    if has_started:
        return "YELLOW", "Upload attempted — outcome uncertain"
    return "YELLOW", "Upload events detected — review needed"


def fmt_bytes(n):
    if n is None: return "unknown"
    for unit in ["B","KB","MB","GB"]:
        if n < 1024: return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def esc(text):
    """HTML-escape text."""
    return html.escape(str(text))


def read_json_file(path, warn_on_error=False):
    """Read and parse a JSON file, returning None on missing file or parse error.

    When warn_on_error is True, a file that exists but cannot be read or parsed
    emits a warning instead of being silently swallowed (a missing file is
    still treated as a normal, silent None).
    """
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except (json.JSONDecodeError, OSError) as e:
        if warn_on_error:
            warn(f"Could not read {path}: {e}")
        return None


def critical_files(sensitive_files):
    """Return only the CRITICAL-severity entries from a sensitive-files list."""
    return [s for s in sensitive_files if s[3] == "CRITICAL"]


def detail_row(label, value, value_class="", extra=""):
    """Render a labeled detail row. `value_class` adds classes to the value span;
    `extra` is appended raw after the value span (e.g. a trailing muted note)."""
    cls = f"value {value_class}" if value_class else "value"
    return (
        f'<div class="detail-row"><span class="label">{label}</span>'
        f'<span class="{cls}">{value}</span>{extra}</div>'
    )


def badge(text, badge_class):
    """Render a colored status badge span."""
    return f'<span class="badge {badge_class}">{text}</span>'


def generate_html_report(grok_home, entries, uploads, telemetry):
    home = Path.home()

    # Scan sensitive files
    all_sensitive = []
    scanned = set()
    for u in uploads:
        path = u.get("repo_path", "")
        if path and path != "unknown" and path not in scanned:
            scanned.add(path)
            all_sensitive.extend(check_sensitive_files(path))

    risk, risk_desc = assess_risk(uploads, all_sensitive)

    # Sort sensitive files by severity
    all_sensitive.sort(key=lambda x: SEVERITY_ORDER.get(x[3], len(SEVERITY_LEVELS)))

    # Auth data
    auth_info = {}
    auth_data = read_json_file(grok_home / "auth.json", warn_on_error=True)
    if isinstance(auth_data, dict):
        for scope, info in auth_data.items():
            auth_info = info
            break
    elif auth_data is not None:
        warn(f"Unexpected structure in {grok_home / 'auth.json'}; skipping auth details")

    # Version
    grok_version = "unknown"
    version_data = read_json_file(grok_home / "version.json", warn_on_error=True)
    if isinstance(version_data, dict):
        grok_version = version_data.get("version", "?")

    # ── Generate HTML ────────────────────────────────────────────────────────

    risk_colors = {
        "GREEN":  {"bg": "#0d5c2e", "light": "#1a7a3f", "text": "#4ade80", "circle": "#22c55e", "label": "NO EXPOSURE"},
        "YELLOW": {"bg": "#6b5a0d", "light": "#8a7215", "text": "#facc15", "circle": "#eab308", "label": "POSSIBLE EXPOSURE"},
        "RED":    {"bg": "#5c0d0d", "light": "#7a1515", "text": "#f87171", "circle": "#ef4444", "label": "CONFIRMED EXPOSURE"},
    }
    rc = risk_colors[risk]

    # Count severities
    sev_counts = {sev: 0 for sev in SEVERITY_LEVELS}
    for _, _, _, sev in all_sensitive:
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    # ── Upload events HTML ───────────────────────────────────────────────────
    upload_cards = ""
    if not uploads:
        upload_cards = '<div class="empty-state">No upload events detected</div>'
    else:
        for i, u in enumerate(uploads, 1):
            status = u["status"]
            scope, scope_desc = assess_path_scope(u["repo_path"])

            if status == "confirmed":
                badge_class = "badge-red"
                badge_text = "CONFIRMED UPLOAD"
            elif status == "started":
                badge_class = "badge-yellow"
                badge_text = "ATTEMPTED — outcome unknown"
            elif status == "skipped":
                badge_class = "badge-green"
                badge_text = "SKIPPED"
            else:
                badge_class = "badge-yellow"
                badge_text = status.upper()

            scope_class = "scope-critical" if scope == "CRITICAL" else \
                          "scope-elevated" if scope == "ELEVATED" else "scope-normal"

            gcs_html = ""
            if u.get("gcs_path") and status == "confirmed":
                gcs_html = detail_row("Destination", f'gs://grok-code-session-traces/{esc(u["gcs_path"])}', "mono bad")

            size_html = ""
            if u.get("size_bytes") is not None:
                size_html = detail_row("Size", fmt_bytes(u["size_bytes"]))

            # Telemetry
            session_t = [t for t in telemetry if t["session_id"] == u["session_id"]]
            telem_html = ""
            if session_t:
                st = session_t[0]
                if st["uploads_enabled"]:
                    telem_html = detail_row("Telemetry", "ENABLED", "bad", f'<span class="muted">(reason: {esc(st.get("upload_reason","?"))})</span>')
                else:
                    telem_html = detail_row("Telemetry", "DISABLED", "good")

            if scope_desc:
                scope_html = detail_row("Path scope", f"{scope} — {esc(scope_desc)}", scope_class)
            else:
                scope_html = detail_row("Path scope", scope, "good")

            upload_cards += f'''
        <div class="card upload-card">
          <div class="card-header">
            <span class="upload-num">#{i}</span>
            <span class="timestamp">{esc(u["timestamp"][:19])}</span>
            {badge(badge_text, badge_class)}
          </div>
          <div class="card-body">
            {detail_row("Phase", esc(u["phase"]))}
            {detail_row("Repo path", esc(u["repo_path"]), "mono path")}
            {scope_html}
            {gcs_html}
            {size_html}
            {telem_html}
          </div>
        </div>'''

    # ── Sensitive files HTML ─────────────────────────────────────────────────
    sensitive_html = ""
    if not uploads:
        sensitive_html = '<div class="empty-state">No upload paths to scan</div>'
    elif all_sensitive:
        sev_legend = ""
        for sev in SEVERITY_LEVELS:
            count = sev_counts.get(sev, 0)
            if count:
                color = SEVERITY_COLORS[sev]
                sev_legend += f'<span class="sev-pill" style="background:{color}">{sev} ({count})</span> '

        sensitive_html = f'<div class="sev-legend">{sev_legend}</div>'

        for _, desc, path, severity in all_sensitive:
            color = SEVERITY_COLORS.get(severity, SEVERITY_FALLBACK_COLOR)
            file_exists = Path(path).exists()
            exists_badge = '<span class="file-exists">EXISTS</span>' if file_exists else '<span class="file-gone">removed</span>'
            sensitive_html += f'''
        <div class="sensitive-item sev-{severity.lower()}">
          <div class="sensitive-marker" style="background:{color}"></div>
          <div class="sensitive-content">
            <div class="sensitive-desc">{esc(desc)} <span class="sev-badge" style="background:{color}">{severity}</span> {exists_badge}</div>
            <div class="sensitive-path mono">{esc(path)}</div>
          </div>
        </div>'''
    else:
        sensitive_html = '<div class="empty-state good">No sensitive files found in upload paths</div>'

    # ── Telemetry HTML ───────────────────────────────────────────────────────
    telemetry_html = ""
    if telemetry:
        sessions = {}
        for t in telemetry:
            sid = t["session_id"]
            if sid not in sessions:
                sessions[sid] = t

        for sid, t in sessions.items():
            enabled = t["uploads_enabled"]
            status_class = "telemetry-on" if enabled else "telemetry-off"
            status_text = "ENABLED" if enabled else "DISABLED"
            reason_html = f'<span class="muted">(reason: {esc(t.get("upload_reason","?"))})</span>' if enabled else ""
            telemetry_html += f'''
        <div class="telemetry-row {status_class}">
          <span class="mono">{esc(sid[:12])}...</span>
          <span class="timestamp">{esc(t["timestamp"][:10])}</span>
          {badge(status_text, 'badge-red' if enabled else 'badge-green')}
          {reason_html}
        </div>'''

    # ── Auth HTML ────────────────────────────────────────────────────────────
    auth_html = ""
    if auth_info:
        opt_out = auth_info.get("coding_data_retention_opt_out")
        if opt_out is False:
            auth_html += detail_row("Data retention opt-out", "NOT OPTED OUT", "bad", '<span class="muted">xAI can retain your data</span>')
        elif opt_out is True:
            auth_html += detail_row("Data retention opt-out", "OPTED OUT", "good")
        else:
            auth_html += detail_row("Data retention opt-out", "UNKNOWN")

        name = f"{auth_info.get('first_name','')} {auth_info.get('last_name','')}".strip()
        if name:
            auth_html += detail_row("Identity", esc(name))
        if auth_info.get("email"):
            auth_html += detail_row("Email", esc(auth_info["email"]))

    # ── Actions HTML ─────────────────────────────────────────────────────────
    actions_html = ""
    if risk == "GREEN":
        actions_html = """
        <div class="action-item good">
          <span class="action-icon">✓</span>
          <span>You're clear. Stay safe:</span>
        </div>
        <ol class="action-list">
          <li>Always launch <code>grok</code> from inside a project directory</li>
          <li>Never run <code>grok</code> from your home directory or <code>/</code></li>
          <li>Re-run this check after Grok updates</li>
          <li>Set <code>coding_data_retention_opt_out = true</code> in auth.json</li>
        </ol>"""
    elif risk == "YELLOW":
        actions_html = """
        <div class="action-item warning">
          <span class="action-icon">⚠</span>
          <span>Possible exposure — take action:</span>
        </div>"""
        if all_sensitive:
            crit_files = critical_files(all_sensitive)
            if crit_files:
                actions_html += '<div class="action-subsection">IMMEDIATE — Rotate these credentials:</div><ul class="action-list">'
                for _, desc, path, sev in crit_files[:6]:
                    actions_html += f'<li class="sev-critical"><strong>{esc(desc)}</strong><br><span class="mono small">{esc(path)}</span></li>'
                remaining = len(all_sensitive) - len(crit_files)
                if remaining > 0:
                    actions_html += f'<li class="muted">+ {remaining} HIGH/MEDIUM files to review</li>'
                actions_html += '</ul>'
        actions_html += """
        <div class="action-subsection">PREVENT</div>
        <ul class="action-list">
          <li>Always <code>cd</code> into project dirs before running grok</li>
          <li>Verify telemetry is off before each session</li>
          <li>Set <code>coding_data_retention_opt_out = true</code> in auth.json</li>
          <li>Delete <code>~/.grok/upload_queue/</code></li>
        </ul>"""
    elif risk == "RED":
        actions_html = """
        <div class="action-item critical">
          <span class="action-icon">⛔</span>
          <span>Confirmed exposure — act now:</span>
        </div>
        <div class="action-subsection critical-text">IMMEDIATE — Do these right now:</div>"""
        crit_files = critical_files(all_sensitive)
        if crit_files:
            actions_html += '<ol class="action-list">'
            actions_html += '<li><strong class="critical-text">Rotate ALL CRITICAL credentials:</strong><ul>'
            for _, desc, path, sev in crit_files[:8]:
                actions_html += f'<li class="sev-critical">{esc(desc)}<br><span class="mono small">{esc(path)}</span></li>'
            remaining = len(all_sensitive) - len(crit_files)
            if remaining > 0:
                actions_html += f'<li class="muted">+ {remaining} HIGH/MEDIUM files to review</li>'
            actions_html += '</ul></li>'
            actions_html += """<li><strong>Regenerate SSH keys:</strong> <code>ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519</code></li>
            <li><strong>Revoke and recreate API tokens</strong> stored in files</li>
            <li>If <code>~/.hermes/</code> was included: review memories/config for secrets</li>
          </ol>"""
        actions_html += """
        <div class="action-subsection">HARDENING — Prevent recurrence:</div>
        <ol class="action-list" start="5">
          <li>Set <code>coding_data_retention_opt_out = true</code> in auth.json</li>
          <li>Delete <code>~/.grok/upload_queue/</code></li>
          <li>Only run grok inside project directories</li>
          <li>Re-run this exposure check periodically</li>
          <li>Contact xAI to request data deletion from:<br><code>gs://grok-code-session-traces/</code></li>
        </ol>"""

    # ── Version badge ────────────────────────────────────────────────────────
    version_badge = ""
    if grok_version != "unknown":
        if grok_version < "0.2.90":
            version_badge = badge("Pre-0.2.90 — folder-trust fix missing", "badge-yellow")
        else:
            version_badge = badge(f"v{esc(grok_version)} — folder-trust fix present", "badge-green")

    # ── Scan warnings HTML ───────────────────────────────────────────────────
    # Surface any non-fatal problems so incomplete scans are visible rather
    # than being silently absent from the report.
    warnings_html = ""
    if WARNINGS:
        warn_items = "".join(f"<li>{esc(w)}</li>" for w in WARNINGS)
        warnings_html = f'''
    <div class="section">
      <div class="section-title">Scan Warnings ({len(WARNINGS)})</div>
      <div class="card"><div class="card-body">
        <div class="action-item warning"><span class="action-icon">⚠</span><span>Some data could not be read — results may be incomplete.</span></div>
        <ul class="action-list">{warn_items}</ul>
      </div></div>
    </div>'''

    # ── Assemble full HTML ───────────────────────────────────────────────────
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Grok Data Exposure Report — {now}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
      background: #f5f5f5;
      color: #1a1a1a;
      padding: 20px;
      line-height: 1.6;
    }}
    .container {{ max-width: 900px; margin: 0 auto; }}

    /* Header */
    .report-header {{
      text-align: center;
      padding: 30px 20px;
      border-bottom: 1px solid #ddd;
      margin-bottom: 30px;
    }}
    .report-header h1 {{ font-size: 1.5rem; color: #1a1a1a; font-weight: 700; letter-spacing: 1px; }}
    .report-header .subtitle {{ color: #555; font-size: 0.85rem; margin-top: 5px; }}

    /* Traffic Light */
    .traffic-light {{
      background: #fff;
      border: 1px solid #ddd;
      border-radius: 12px;
      padding: 40px 30px;
      text-align: center;
      margin-bottom: 30px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.06);
    }}
    .light-circle {{
      width: 80px; height: 80px;
      border-radius: 50%;
      background: {rc['circle']};
      margin: 0 auto 20px;
      box-shadow: 0 0 30px {rc['circle']}, inset 0 -4px 12px rgba(0,0,0,0.15);
      animation: pulse 2s ease-in-out infinite;
    }}
    @keyframes pulse {{ 0%,100% {{ opacity: 1; }} 50% {{ opacity: 0.65; }} }}
    .light-label {{ font-size: 1.8rem; font-weight: 800; color: {rc['text']}; letter-spacing: 2px; }}
    .light-desc {{ font-size: 1rem; color: #444; margin-top: 10px; }}

    /* Sections */
    .section {{
      margin-bottom: 30px;
    }}
    .section-title {{
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 2px;
      color: #555;
      border-bottom: 2px solid #d0d0d0;
      padding-bottom: 10px;
      margin-bottom: 15px;
      font-weight: 700;
    }}

    /* System info */
    .sys-info {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 5px 20px;
      font-size: 0.85rem;
      color: #333;
    }}
    .sys-info span:nth-child(odd) {{ color: #555; font-weight: 600; }}

    /* Cards */
    .card {{
      background: #fff;
      border: 1px solid #e0e0e0;
      border-radius: 8px;
      margin-bottom: 15px;
      overflow: hidden;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }}
    .card-header {{
      padding: 12px 16px;
      border-bottom: 1px solid #eee;
      display: flex;
      align-items: center;
      gap: 12px;
      background: #fafafa;
    }}
    .upload-num {{ font-weight: 700; color: #333; font-size: 0.85rem; }}
    .timestamp {{ color: #555; font-size: 0.8rem; font-family: 'SF Mono', Monaco, monospace; }}
    .card-body {{ padding: 12px 16px; }}

    /* Detail rows */
    .detail-row {{
      display: flex;
      align-items: baseline;
      gap: 8px;
      padding: 3px 0;
      font-size: 0.85rem;
    }}
    .detail-row .label {{ color: #555; min-width: 100px; text-align: right; font-weight: 600; }}
    .detail-row .value {{ color: #1a1a1a; }}
    .detail-row .value.mono, .mono {{ font-family: 'SF Mono', Monaco, 'Courier New', monospace; }}
    .detail-row .value.path {{ color: #7c3aed; word-break: break-all; }}

    /* Badges */
    .badge {{
      display: inline-block;
      padding: 2px 10px;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 700;
      letter-spacing: 0.5px;
      margin-left: auto;
    }}
    .badge-red {{ background: #ef4444; color: #fff; }}
    .badge-yellow {{ background: #f59e0b; color: #fff; }}
    .badge-green {{ background: #10b981; color: #fff; }}

    /* Path scope */
    .scope-critical {{ color: #dc2626; font-weight: 700; }}
    .scope-elevated {{ color: #d97706; }}
    .scope-normal {{ color: #059669; }}

    /* Value modifiers */
    .bad {{ color: #dc2626; }}
    .good {{ color: #059669; }}
    .muted {{ color: #666; font-size: 0.8rem; }}

    /* Sensitive files */
    .sev-legend {{ margin-bottom: 15px; display: flex; gap: 8px; flex-wrap: wrap; }}
    .sev-pill {{
      display: inline-block;
      padding: 3px 12px;
      border-radius: 12px;
      font-size: 0.7rem;
      font-weight: 700;
      color: #fff;
    }}
    .sensitive-item {{
      display: flex;
      align-items: stretch;
      background: #fff;
      border: 1px solid #e0e0e0;
      border-radius: 6px;
      margin-bottom: 8px;
      overflow: hidden;
      box-shadow: 0 1px 2px rgba(0,0,0,0.04);
    }}
    .sensitive-marker {{ width: 4px; flex-shrink: 0; }}
    .sensitive-content {{ padding: 10px 14px; flex: 1; }}
    .sensitive-desc {{ font-size: 0.85rem; color: #1a1a1a; }}
    .sensitive-path {{ font-size: 0.75rem; color: #555; margin-top: 3px; word-break: break-all; }}
    .sev-badge {{
      display: inline-block;
      padding: 1px 6px;
      border-radius: 3px;
      font-size: 0.65rem;
      font-weight: 700;
      color: #fff;
      margin-left: 6px;
    }}
    .file-exists {{
      display: inline-block;
      padding: 1px 6px;
      border-radius: 3px;
      font-size: 0.65rem;
      background: #fee2e2;
      color: #dc2626;
      margin-left: 6px;
      font-weight: 600;
    }}
    .file-gone {{
      display: inline-block;
      padding: 1px 6px;
      border-radius: 3px;
      font-size: 0.65rem;
      background: #f3f4f6;
      color: #666;
      margin-left: 6px;
    }}

    /* Telemetry */
    .telemetry-row {{
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 8px 14px;
      background: #fff;
      border: 1px solid #e0e0e0;
      border-radius: 6px;
      margin-bottom: 6px;
      font-size: 0.8rem;
    }}
    .telemetry-on {{ border-left: 3px solid #ef4444; }}
    .telemetry-off {{ border-left: 3px solid #10b981; }}

    /* Actions */
    .action-item {{
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 12px 16px;
      border-radius: 8px;
      font-size: 0.95rem;
      font-weight: 600;
      margin-bottom: 15px;
    }}
    .action-item.good {{ background: #ecfdf5; border: 1px solid #a7f3d0; color: #065f46; }}
    .action-item.warning {{ background: #fffbeb; border: 1px solid #fde68a; color: #92400e; }}
    .action-item.critical {{ background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; }}
    .action-icon {{ font-size: 1.3rem; }}
    .action-subsection {{
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #555;
      margin: 15px 0 10px;
      font-weight: 700;
    }}
    .critical-text {{ color: #dc2626; }}
    .action-list {{
      list-style: none;
      padding-left: 0;
    }}
    .action-list li {{
      padding: 8px 0 8px 24px;
      position: relative;
      font-size: 0.85rem;
      color: #333;
    }}
    .action-list li::before {{
      content: '\\25B8';
      position: absolute;
      left: 8px;
      color: #777;
    }}
    .action-list code {{
      background: #f3f4f6;
      padding: 1px 6px;
      border-radius: 3px;
      font-size: 0.8rem;
      color: #7c3aed;
      border: 1px solid #e5e7eb;
    }}
    .sev-critical {{ color: #dc2626; }}
    .small {{ font-size: 0.75rem; }}
    .empty-state {{
      text-align: center;
      padding: 30px;
      color: #666;
      font-style: italic;
    }}
    .empty-state.good {{ color: #059669; font-style: normal; }}

    /* Footer */
    .footer {{
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid #d0d0d0;
      font-size: 0.75rem;
      color: #555;
      text-align: center;
    }}
    .footer code {{ background: #f3f4f6; padding: 1px 4px; border-radius: 2px; }}

    /* Upload card accent borders */
    .upload-card {{ border-left: 3px solid #e0e0e0; }}
    .upload-card.badge-red {{ border-left-color: #ef4444; }}
    .upload-card.badge-yellow {{ border-left-color: #f59e0b; }}
    .upload-card.badge-green {{ border-left-color: #10b981; }}
  </style>
</head>
<body>
  <div class="container">

    <div class="report-header">
      <h1>GROK DATA EXPOSURE REPORT</h1>
      <div class="subtitle">Generated {now} · grok-data-exposure-checker v3.0</div>
    </div>

    <!-- Traffic Light -->
    <div class="traffic-light">
      <div class="light-circle"></div>
      <div class="light-label">{risk}</div>
      <div class="light-desc">{esc(risk_desc)}</div>
    </div>

    <!-- System -->
    <div class="section">
      <div class="section-title">System</div>
      <div class="sys-info">
        <span>Grok home</span><span class="mono">{esc(grok_home)}</span>
        <span>User home</span><span class="mono">{esc(home)}</span>
        <span>Platform</span><span>{esc(sys.platform)}</span>
        <span>Log entries</span><span>{len(entries)}</span>
        <span>Version</span><span>{version_badge or esc(grok_version)}</span>
      </div>
    </div>
{warnings_html}

    <!-- Upload Events -->
    <div class="section">
      <div class="section-title">Upload Events ({len(uploads)})</div>
      {upload_cards}
    </div>

    <!-- Sensitive Files -->
    <div class="section">
      <div class="section-title">Sensitive Files in Upload Paths ({len(all_sensitive)})</div>
      {sensitive_html}
    </div>

    <!-- Telemetry -->
    {f'''<div class="section">
      <div class="section-title">Telemetry History</div>
      {telemetry_html}
    </div>''' if telemetry else ''}

    <!-- Auth -->
    {f'''<div class="section">
      <div class="section-title">Auth &amp; Data Retention</div>
      <div class="card"><div class="card-body">{auth_html}</div></div>
    </div>''' if auth_html else ''}

    <!-- Actions -->
    <div class="section">
      <div class="section-title">Recommended Actions</div>
      {actions_html}
    </div>

    <!-- Footer -->
    <div class="footer">
      <p>Data destination: <code>gs://grok-code-session-traces</code> (xAI private GCS)</p>
      <p>Upload route: <code>cli-chat-proxy.grok.com → GCS</code></p>
      <p>This tool checks local logs only. Server-side data may differ.</p>
    </div>

  </div>
</body>
</html>"""

    return html_content, risk, risk_desc, all_sensitive


def main():
    grok_home = get_grok_home()

    if not grok_home.exists():
        print(f"\n  ERROR: Grok installation not found at {grok_home}")
        print(f"  Set GROK_HOME if installed elsewhere.\n")
        sys.exit(1)

    log_file = grok_home / "logs" / "unified.jsonl"
    if not log_file.exists():
        print(f"\n  ERROR: No log file at {log_file}")
        print(f"  Grok may not have been used yet.\n")
        sys.exit(1)

    try:
        entries = parse_logs(log_file)
    except OSError as e:
        print(f"\n  ERROR: Could not read log file {log_file}: {e}")
        print(f"  Exposure cannot be assessed without reading the log; "
              f"an unreadable log is NOT the same as 'no exposure'.")
        print(f"  Check file permissions and try again.\n")
        sys.exit(1)
    uploads, telemetry = analyze_uploads(entries)

    html_content, risk, risk_desc, sensitive_files = generate_html_report(grok_home, entries, uploads, telemetry)

    # Save HTML report. The report embeds the user's identity and a map of which
    # sensitive credential files exist on this machine, so restrict it to the
    # owner (0600) instead of the umask default (commonly world-readable 0644).
    report_path = grok_home / "exposure-report.html"
    try:
        fd = os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(html_content)
    except OSError as e:
        print(f"\n  ERROR: Could not write report to {report_path}: {e}\n",
              file=sys.stderr)
        sys.exit(1)
    try:
        os.chmod(report_path, 0o600)  # enforce even if the file pre-existed
    except OSError as e:
        warn(f"Could not restrict report permissions on {report_path}: {e}")

    # Terminal summary
    print()
    if risk == "GREEN":
        print(f"  ● GREEN — No data exposure detected")
    elif risk == "YELLOW":
        print(f"  ● YELLOW — Possible data exposure")
    elif risk == "RED":
        print(f"  ● RED — Confirmed data exposure")

    crit_count = sum(1 for s in sensitive_files if s[3] == "CRITICAL")
    if crit_count:
        print(f"  {crit_count} CRITICAL sensitive file(s) found")

    if WARNINGS:
        print(f"  {len(WARNINGS)} warning(s) reported above — "
              f"results may be incomplete")

    print(f"\n  Report saved: {report_path}")
    print(f"  Open with:    xdg-open {report_path}")
    print()

    # Try to open in browser. A failure here is non-fatal (headless
    # environments have no browser) but should not be silent.
    try:
        opened = webbrowser.open(f"file://{report_path}")
    except Exception as e:
        warn(f"Could not open report in browser: {e}")
    else:
        if not opened:
            warn("No browser available to open the report automatically")


if __name__ == "__main__":
    main()
