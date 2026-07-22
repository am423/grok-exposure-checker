"""Unit tests for generate_html_report."""

import json

import pytest


def _upload(status="confirmed", repo_path="/home/u/proj", phase="before_codebase",
            sid="s1", gcs_path="b/before_codebase/1", size_bytes=2048, ts="2026-07-01T10:00:00Z"):
    return {
        "timestamp": ts, "session_id": sid, "phase": phase,
        "repo_path": repo_path, "max_file_bytes": None,
        "status": status, "gcs_path": gcs_path, "size_bytes": size_bytes,
    }


class TestGenerateHtmlReport:
    def test_no_uploads_is_green_report(self, gec, tmp_path):
        html, risk, desc, sensitive = gec.generate_html_report(tmp_path, [], [], [])
        assert risk == "GREEN"
        assert sensitive == []
        assert "<!DOCTYPE html>" in html
        assert "GROK DATA EXPOSURE REPORT" in html
        assert "No upload events detected" in html
        assert ">GREEN<" in html

    def test_confirmed_upload_with_sensitive_is_red(self, gec, tmp_path):
        repo = tmp_path / "proj"
        repo.mkdir()
        (repo / ".env").write_text("SECRET=1")
        uploads = [_upload(repo_path=str(repo))]
        html, risk, desc, sensitive = gec.generate_html_report(tmp_path, [], uploads, [])
        assert risk == "RED"
        assert any(s[3] == "CRITICAL" for s in sensitive)
        assert "CONFIRMED UPLOAD" in html
        assert "gs://grok-code-session-traces/" in html

    def test_repo_path_is_html_escaped(self, gec, tmp_path):
        uploads = [_upload(status="started", repo_path="/x/<script>evil</script>",
                           gcs_path=None, size_bytes=None)]
        html, risk, _, _ = gec.generate_html_report(tmp_path, [], uploads, [])
        assert "<script>evil</script>" not in html
        assert "&lt;script&gt;evil&lt;/script&gt;" in html

    def test_auth_not_opted_out_rendered(self, gec, tmp_path):
        auth = {"scope1": {
            "coding_data_retention_opt_out": False,
            "email": "user@example.com",
            "first_name": "Ada", "last_name": "Lovelace",
        }}
        (tmp_path / "auth.json").write_text(json.dumps(auth))
        html, *_ = gec.generate_html_report(tmp_path, [], [], [])
        assert "NOT OPTED OUT" in html
        assert "user@example.com" in html
        assert "Ada Lovelace" in html

    def test_auth_opted_out_rendered(self, gec, tmp_path):
        auth = {"s": {"coding_data_retention_opt_out": True}}
        (tmp_path / "auth.json").write_text(json.dumps(auth))
        html, *_ = gec.generate_html_report(tmp_path, [], [], [])
        assert "OPTED OUT" in html
        assert "NOT OPTED OUT" not in html

    def test_malformed_auth_json_ignored(self, gec, tmp_path):
        (tmp_path / "auth.json").write_text("{not json")
        html, risk, *_ = gec.generate_html_report(tmp_path, [], [], [])
        assert risk == "GREEN"  # still produces a report

    def test_old_version_flags_missing_fix(self, gec, tmp_path):
        (tmp_path / "version.json").write_text(json.dumps({"version": "0.2.50"}))
        html, *_ = gec.generate_html_report(tmp_path, [], [], [])
        assert "folder-trust fix missing" in html

    def test_new_version_flags_present_fix(self, gec, tmp_path):
        (tmp_path / "version.json").write_text(json.dumps({"version": "0.3.00"}))
        html, *_ = gec.generate_html_report(tmp_path, [], [], [])
        assert "folder-trust fix present" in html

    def test_telemetry_section_present(self, gec, tmp_path):
        telemetry = [{
            "timestamp": "2026-07-01T10:00:00Z", "session_id": "abcdef123456xyz",
            "uploads_enabled": True, "upload_reason": "server_flag",
        }]
        uploads = [_upload(sid="abcdef123456xyz")]
        html, *_ = gec.generate_html_report(tmp_path, [], uploads, telemetry)
        assert "Telemetry History" in html
        assert "ENABLED" in html

    def test_skipped_upload_is_green(self, gec, tmp_path):
        uploads = [_upload(status="skipped", gcs_path="skipped: not_trusted", size_bytes=None)]
        html, risk, _, _ = gec.generate_html_report(tmp_path, [], uploads, [])
        assert risk == "GREEN"
        assert "SKIPPED" in html

    def test_yellow_actions_list_critical_files(self, gec, tmp_path):
        repo = tmp_path / "proj"
        repo.mkdir()
        (repo / ".env").write_text("x")  # CRITICAL, but upload only "started" -> YELLOW
        uploads = [_upload(status="started", repo_path=str(repo), gcs_path=None, size_bytes=None)]
        html, risk, _, _ = gec.generate_html_report(tmp_path, [], uploads, [])
        assert risk == "YELLOW"
        assert "Possible exposure" in html
        assert "Rotate these credentials" in html

    def test_telemetry_disabled_renders_in_card(self, gec, tmp_path):
        telemetry = [{
            "timestamp": "2026-07-01T10:00:00Z", "session_id": "sess1",
            "uploads_enabled": False, "upload_reason": None,
        }]
        uploads = [_upload(sid="sess1")]
        html, *_ = gec.generate_html_report(tmp_path, [], uploads, telemetry)
        assert "DISABLED" in html

    def test_auth_unknown_opt_out(self, gec, tmp_path):
        (tmp_path / "auth.json").write_text(json.dumps({"s": {"email": "e@x.com"}}))
        html, *_ = gec.generate_html_report(tmp_path, [], [], [])
        assert "UNKNOWN" in html

    def test_sensitive_files_sorted_critical_first(self, gec, tmp_path):
        repo = tmp_path / "proj"
        repo.mkdir()
        (repo / ".env").write_text("x")          # CRITICAL
        (repo / "server.pem").write_text("x")    # HIGH
        _, _, _, sensitive = gec.generate_html_report(tmp_path, [], [_upload(repo_path=str(repo))], [])
        severities = [s[3] for s in sensitive]
        assert severities == sorted(severities, key=lambda s: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[s])
        assert severities[0] == "CRITICAL"
