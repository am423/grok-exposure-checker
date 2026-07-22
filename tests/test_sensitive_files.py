"""Unit tests for check_sensitive_files."""

import pytest


def _by_path(results):
    return {path: (rel, desc, sev) for rel, desc, path, sev in results}


class TestCheckSensitiveFiles:
    def test_nonexistent_base_returns_empty(self, gec, tmp_path):
        assert gec.check_sensitive_files(tmp_path / "nope") == []

    def test_file_instead_of_dir_returns_empty(self, gec, tmp_path):
        f = tmp_path / "afile"
        f.write_text("x")
        assert gec.check_sensitive_files(f) == []

    def test_empty_dir_returns_empty(self, gec, tmp_path):
        assert gec.check_sensitive_files(tmp_path) == []

    def test_detects_listed_sensitive_files_with_severity(self, gec, tmp_path):
        (tmp_path / ".ssh").mkdir()
        (tmp_path / ".ssh" / "id_rsa").write_text("KEY")
        (tmp_path / ".env").write_text("SECRET=1")
        (tmp_path / ".aws").mkdir()
        (tmp_path / ".aws" / "credentials").write_text("creds")

        results = _by_path(gec.check_sensitive_files(tmp_path))
        assert results[str(tmp_path / ".ssh" / "id_rsa")][2] == "CRITICAL"
        assert results[str(tmp_path / ".env")][2] == "CRITICAL"
        assert results[str(tmp_path / ".aws" / "credentials")][2] == "CRITICAL"

    def test_does_not_report_absent_files(self, gec, tmp_path):
        (tmp_path / ".env").write_text("x")
        results = _by_path(gec.check_sensitive_files(tmp_path))
        assert str(tmp_path / ".ssh" / "id_rsa") not in results

    def test_glob_matches_pem_file(self, gec, tmp_path):
        (tmp_path / "server.pem").write_text("cert")
        results = _by_path(gec.check_sensitive_files(tmp_path))
        assert results[str(tmp_path / "server.pem")][2] == "HIGH"

    def test_glob_matches_key_in_subdirectory(self, gec, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "private.key").write_text("k")
        results = _by_path(gec.check_sensitive_files(tmp_path))
        assert str(sub / "private.key") in results

    def test_ssh_id_scan_only_when_base_is_home(self, gec, tmp_path, monkeypatch):
        ssh = tmp_path / ".ssh"
        ssh.mkdir()
        (ssh / "id_customname").write_text("k")
        # base != home -> the extra id_* scan is skipped
        monkeypatch.setenv("HOME", str(tmp_path / "elsewhere"))
        results = _by_path(gec.check_sensitive_files(tmp_path))
        assert str(ssh / "id_customname") not in results

    def test_ssh_id_scan_runs_when_base_is_home(self, gec, tmp_path, monkeypatch):
        ssh = tmp_path / ".ssh"
        ssh.mkdir()
        (ssh / "id_customname").write_text("k")
        monkeypatch.setenv("HOME", str(tmp_path))
        results = _by_path(gec.check_sensitive_files(tmp_path))
        assert results[str(ssh / "id_customname")][2] == "CRITICAL"

    def test_results_are_deduped_by_path(self, gec, tmp_path, monkeypatch):
        # id_rsa is matched both by the static list and the id_* scan; it
        # must appear only once in the output.
        ssh = tmp_path / ".ssh"
        ssh.mkdir()
        (ssh / "id_rsa").write_text("k")
        monkeypatch.setenv("HOME", str(tmp_path))
        results = gec.check_sensitive_files(tmp_path)
        paths = [r[2] for r in results]
        assert paths.count(str(ssh / "id_rsa")) == 1
