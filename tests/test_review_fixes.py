"""Tests for the review-fix behaviors: numeric version parsing, UNKNOWN path
scope, session-based upload matching, recursive secret scanning, and the
platform-aware open command."""

import pytest


class TestParseVersion:
    def test_numeric_tuple(self, gec):
        assert gec.parse_version("0.2.90") == (0, 2, 90)

    def test_100_is_newer_than_90(self, gec):
        # The lexicographic bug this replaces sorted "0.2.100" before "0.2.90".
        assert gec.parse_version("0.2.100") > gec.parse_version("0.2.90")

    def test_ignores_suffix(self, gec):
        assert gec.parse_version("0.2.90-rc1") == (0, 2, 90)

    def test_unparseable_returns_none(self, gec):
        assert gec.parse_version("unknown") is None
        assert gec.parse_version("") is None


class TestAssessPathScopeReview:
    @pytest.fixture
    def fake_home(self, monkeypatch):
        monkeypatch.setenv("HOME", "/home/testuser")
        return "/home/testuser"

    def test_literal_unknown_is_unknown(self, gec, fake_home):
        scope, desc = gec.assess_path_scope("unknown")
        assert scope == "UNKNOWN"
        assert "not recorded" in desc

    def test_missing_path_is_unknown_not_elevated(self, gec, fake_home, tmp_path):
        # A logged path that no longer exists on this machine must not be
        # asserted as ELEVATED (we cannot verify its scope).
        missing = tmp_path / "was-here-once"
        scope, desc = gec.assess_path_scope(str(missing))
        assert scope == "UNKNOWN"
        assert "unverifiable" in desc


class TestUploadMatching:
    def _entry(self, msg, ctx, sid="s", ts="t"):
        return {"msg": msg, "ctx": ctx, "sid": sid, "ts": ts}

    def test_phaseless_enqueue_confirms_started_no_duplicate(self, gec):
        # enqueue whose gcs_path lacks a phase marker should confirm the
        # pending start in the same session rather than create a 2nd card.
        entries = [
            self._entry("repo_state.upload.start",
                        {"phase": "before_codebase", "repo_path": "/p"}),
            self._entry("repo_state.upload.enqueued",
                        {"gcs_path": "traces/no-marker/abc", "size_bytes": 10}),
        ]
        uploads, _ = gec.analyze_uploads(entries)
        assert len(uploads) == 1
        assert uploads[0]["status"] == "confirmed"
        assert uploads[0]["repo_path"] == "/p"


class TestRecursiveScan:
    def test_finds_deep_env_file(self, gec, tmp_path):
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        (deep / ".env").write_text("SECRET=1")
        results = gec.check_sensitive_files(tmp_path)
        paths = [r[2] for r in results]
        assert str(deep / ".env") in paths
        sev = next(r[3] for r in results if r[2] == str(deep / ".env"))
        assert sev == "CRITICAL"

    def test_skips_runtime_noise_dirs(self, gec, tmp_path):
        noise = tmp_path / ".pyenv" / "versions"
        noise.mkdir(parents=True)
        (noise / "cert.pem").write_text("x")
        results = gec.check_sensitive_files(tmp_path)
        assert str(noise / "cert.pem") not in [r[2] for r in results]


class TestOpenCommand:
    def test_linux(self, gec, monkeypatch):
        monkeypatch.setattr(gec.sys, "platform", "linux")
        assert gec.open_command() == "xdg-open"

    def test_macos(self, gec, monkeypatch):
        monkeypatch.setattr(gec.sys, "platform", "darwin")
        assert gec.open_command() == "open"

    def test_windows(self, gec, monkeypatch):
        monkeypatch.setattr(gec.sys, "platform", "win32")
        assert gec.open_command() == "start"
