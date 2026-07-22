"""Integration-style tests for the main() entry point."""

import json

import pytest


@pytest.fixture
def grok_home(tmp_path, monkeypatch):
    home = tmp_path / ".grok"
    monkeypatch.setenv("GROK_HOME", str(home))
    return home


def _make_logs(home, lines):
    logs = home / "logs"
    logs.mkdir(parents=True)
    (logs / "unified.jsonl").write_text("\n".join(json.dumps(l) for l in lines))


class TestMain:
    def test_missing_grok_home_exits(self, gec, grok_home, capsys):
        with pytest.raises(SystemExit) as exc:
            gec.main()
        assert exc.value.code == 1
        assert "Grok installation not found" in capsys.readouterr().out

    def test_missing_log_file_exits(self, gec, grok_home, capsys):
        grok_home.mkdir(parents=True)
        with pytest.raises(SystemExit) as exc:
            gec.main()
        assert exc.value.code == 1
        assert "No log file" in capsys.readouterr().out

    def test_green_run_writes_report(self, gec, grok_home, capsys, monkeypatch):
        opened = []
        monkeypatch.setattr(gec.webbrowser, "open", lambda url: opened.append(url))
        _make_logs(grok_home, [{"msg": "trace.upload.decision", "ctx": {"uploads_enabled": False}, "sid": "s"}])

        gec.main()

        report = grok_home / "exposure-report.html"
        assert report.exists()
        out = capsys.readouterr().out
        assert "GREEN" in out
        assert str(report) in out
        assert opened  # browser open attempted

    def test_red_run_reports_critical_count(self, gec, grok_home, capsys, monkeypatch, tmp_path):
        monkeypatch.setattr(gec.webbrowser, "open", lambda url: None)
        repo = tmp_path / "proj"
        repo.mkdir()
        (repo / ".env").write_text("SECRET=1")
        _make_logs(grok_home, [
            {"msg": "repo_state.upload.start", "ctx": {"phase": "before_codebase", "repo_path": str(repo)}, "sid": "s"},
            {"msg": "repo_state.upload.enqueued", "ctx": {"gcs_path": "b/before_codebase/1", "size_bytes": 10}, "sid": "s"},
        ])

        gec.main()

        out = capsys.readouterr().out
        assert "RED" in out
        assert "CRITICAL" in out

    def test_browser_open_failure_is_swallowed(self, gec, grok_home, capsys, monkeypatch):
        def boom(url):
            raise RuntimeError("no display")
        monkeypatch.setattr(gec.webbrowser, "open", boom)
        _make_logs(grok_home, [{"msg": "noop", "ctx": {}, "sid": "s"}])

        # Should not raise despite the browser failing to open.
        gec.main()
        assert (grok_home / "exposure-report.html").exists()
