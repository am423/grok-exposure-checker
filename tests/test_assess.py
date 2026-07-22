"""Unit tests for assess_path_scope and assess_risk."""

import pytest


@pytest.fixture
def fake_home(monkeypatch):
    """Pin Path.home() to a stable value via the HOME env var (posix)."""
    monkeypatch.setenv("HOME", "/home/testuser")
    return "/home/testuser"


class TestAssessPathScope:
    def test_home_directory_is_critical(self, gec, fake_home):
        scope, desc = gec.assess_path_scope("/home/testuser")
        assert scope == "CRITICAL"
        assert "HOME" in desc

    def test_home_directory_with_trailing_slash(self, gec, fake_home):
        scope, desc = gec.assess_path_scope("/home/testuser/")
        assert scope == "CRITICAL"

    def test_home_directory_case_insensitive(self, gec, fake_home):
        scope, _ = gec.assess_path_scope("/HOME/TESTUSER")
        assert scope == "CRITICAL"

    def test_root_filesystem_is_critical(self, gec, fake_home):
        scope, desc = gec.assess_path_scope("/")
        assert scope == "CRITICAL"
        assert "ROOT" in desc

    def test_empty_path_treated_as_root(self, gec, fake_home):
        scope, desc = gec.assess_path_scope("")
        assert scope == "CRITICAL"
        assert "ROOT" in desc

    def test_windows_root_is_critical(self, gec, fake_home):
        scope, desc = gec.assess_path_scope("C:\\")
        assert scope == "CRITICAL"
        assert "ROOT" in desc

    def test_parent_of_home_is_critical(self, gec, fake_home):
        scope, desc = gec.assess_path_scope("/home")
        assert scope == "CRITICAL"
        assert "Parent" in desc

    def test_non_git_directory_is_elevated(self, gec, fake_home, tmp_path):
        project = tmp_path / "loose-files"
        project.mkdir()
        scope, desc = gec.assess_path_scope(str(project))
        assert scope == "ELEVATED"
        assert "git repo" in desc

    def test_git_repo_is_normal(self, gec, fake_home, tmp_path):
        project = tmp_path / "proj"
        (project / ".git").mkdir(parents=True)
        scope, desc = gec.assess_path_scope(str(project))
        assert scope == "NORMAL"
        assert desc is None


class TestAssessRisk:
    CRIT = [("x", "desc", "/p", "CRITICAL")]

    def test_no_uploads_is_green(self, gec):
        risk, desc = gec.assess_risk([], [])
        assert risk == "GREEN"
        assert "No upload events" in desc

    def test_all_skipped_is_green(self, gec):
        uploads = [{"status": "skipped"}, {"status": "skipped"}]
        risk, desc = gec.assess_risk(uploads, [])
        assert risk == "GREEN"
        assert "skipped" in desc

    def test_confirmed_with_sensitive_is_red(self, gec):
        risk, desc = gec.assess_risk([{"status": "confirmed"}], self.CRIT)
        assert risk == "RED"
        assert "sensitive files" in desc

    def test_confirmed_without_sensitive_is_red(self, gec):
        risk, desc = gec.assess_risk([{"status": "confirmed"}], [])
        assert risk == "RED"
        assert "CONFIRMED data upload" in desc

    def test_started_with_sensitive_is_yellow(self, gec):
        risk, desc = gec.assess_risk([{"status": "started"}], self.CRIT)
        assert risk == "YELLOW"
        assert "sensitive files" in desc

    def test_started_without_sensitive_is_yellow(self, gec):
        risk, desc = gec.assess_risk([{"status": "started"}], [])
        assert risk == "YELLOW"
        assert "outcome uncertain" in desc

    def test_confirmed_takes_precedence_over_started(self, gec):
        uploads = [{"status": "started"}, {"status": "confirmed"}]
        risk, _ = gec.assess_risk(uploads, [])
        assert risk == "RED"

    def test_unknown_status_falls_back_to_yellow(self, gec):
        risk, desc = gec.assess_risk([{"status": "mystery"}], [])
        assert risk == "YELLOW"
        assert "review needed" in desc
