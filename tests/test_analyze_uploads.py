"""Unit tests for analyze_uploads — the log-event state machine."""


def entry(msg, ctx=None, sid="sid-1", ts="2026-07-01T10:00:00Z"):
    return {"msg": msg, "ctx": ctx or {}, "sid": sid, "ts": ts}


class TestAnalyzeUploads:
    def test_empty_entries(self, gec):
        uploads, telemetry = gec.analyze_uploads([])
        assert uploads == []
        assert telemetry == []

    def test_start_event_recorded_as_started(self, gec):
        entries = [entry("repo_state.upload.start", {
            "phase": "before_codebase",
            "repo_path": "/home/user/project",
            "max_file_bytes": 1000,
        })]
        uploads, _ = gec.analyze_uploads(entries)
        assert len(uploads) == 1
        u = uploads[0]
        assert u["status"] == "started"
        assert u["phase"] == "before_codebase"
        assert u["repo_path"] == "/home/user/project"
        assert u["max_file_bytes"] == 1000
        assert u["gcs_path"] is None

    def test_start_missing_ctx_uses_defaults(self, gec):
        uploads, _ = gec.analyze_uploads([entry("repo_state.upload.start")])
        u = uploads[0]
        assert u["phase"] == "unknown"
        assert u["repo_path"] == "unknown"
        assert u["max_file_bytes"] is None

    def test_enqueued_confirms_matching_start(self, gec):
        entries = [
            entry("repo_state.upload.start", {"phase": "before_codebase", "repo_path": "/p"}),
            entry("repo_state.upload.enqueued", {
                "gcs_path": "traces/before_codebase/abc",
                "size_bytes": 2048,
            }),
        ]
        uploads, _ = gec.analyze_uploads(entries)
        assert len(uploads) == 1
        u = uploads[0]
        assert u["status"] == "confirmed"
        assert u["gcs_path"] == "traces/before_codebase/abc"
        assert u["size_bytes"] == 2048

    def test_enqueued_after_codebase_matches_that_phase(self, gec):
        entries = [
            entry("repo_state.upload.start", {"phase": "before_codebase", "repo_path": "/p"}),
            entry("repo_state.upload.start", {"phase": "after_codebase", "repo_path": "/p"}),
            entry("repo_state.upload.enqueued", {"gcs_path": "x/after_codebase/y", "size_bytes": 1}),
        ]
        uploads, _ = gec.analyze_uploads(entries)
        before = next(u for u in uploads if u["phase"] == "before_codebase")
        after = next(u for u in uploads if u["phase"] == "after_codebase")
        assert before["status"] == "started"
        assert after["status"] == "confirmed"

    def test_enqueued_without_matching_start_creates_orphan(self, gec):
        entries = [entry("repo_state.upload.enqueued", {
            "gcs_path": "x/before_codebase/y", "size_bytes": 99,
        })]
        uploads, _ = gec.analyze_uploads(entries)
        assert len(uploads) == 1
        u = uploads[0]
        assert u["status"] == "confirmed"
        assert u["repo_path"] == "unknown"
        assert u["phase"] == "before_codebase"

    def test_enqueued_unknown_phase_when_gcs_has_no_marker(self, gec):
        entries = [entry("repo_state.upload.enqueued", {"gcs_path": "x/y/z"})]
        uploads, _ = gec.analyze_uploads(entries)
        assert uploads[0]["phase"] == "unknown"

    def test_enqueued_does_not_match_different_session(self, gec):
        entries = [
            entry("repo_state.upload.start", {"phase": "before_codebase"}, sid="a"),
            entry("repo_state.upload.enqueued", {"gcs_path": "x/before_codebase/y"}, sid="b"),
        ]
        uploads, _ = gec.analyze_uploads(entries)
        # Start (session a) stays started; enqueued (session b) becomes an orphan.
        assert len(uploads) == 2
        started = next(u for u in uploads if u["session_id"] == "a")
        orphan = next(u for u in uploads if u["session_id"] == "b")
        assert started["status"] == "started"
        assert orphan["status"] == "confirmed"

    def test_skip_marks_started_as_skipped(self, gec):
        entries = [
            entry("repo_state.upload.start", {"phase": "before_codebase"}),
            entry("repo_state.upload.skip", {"reason": "not_trusted"}),
        ]
        uploads, _ = gec.analyze_uploads(entries)
        assert uploads[0]["status"] == "skipped"
        assert uploads[0]["gcs_path"] == "skipped: not_trusted"

    def test_skip_without_reason_defaults_unknown(self, gec):
        entries = [
            entry("repo_state.upload.start", {"phase": "before_codebase"}),
            entry("repo_state.upload.skip", {}),
        ]
        uploads, _ = gec.analyze_uploads(entries)
        assert uploads[0]["gcs_path"] == "skipped: unknown"

    def test_skip_without_prior_start_is_noop(self, gec):
        uploads, _ = gec.analyze_uploads([entry("repo_state.upload.skip", {"reason": "r"})])
        assert uploads == []

    def test_telemetry_decision_collected(self, gec):
        entries = [entry("trace.upload.decision", {
            "uploads_enabled": True, "upload_reason": "server_flag",
        })]
        _, telemetry = gec.analyze_uploads(entries)
        assert telemetry == [{
            "timestamp": "2026-07-01T10:00:00Z",
            "session_id": "sid-1",
            "uploads_enabled": True,
            "upload_reason": "server_flag",
        }]

    def test_unrelated_message_ignored(self, gec):
        uploads, telemetry = gec.analyze_uploads([entry("some.other.event", {"x": 1})])
        assert uploads == []
        assert telemetry == []

    def test_full_confirmed_flow_with_telemetry(self, gec):
        entries = [
            entry("trace.upload.decision", {"uploads_enabled": True, "upload_reason": "flag"}),
            entry("repo_state.upload.start", {"phase": "before_codebase", "repo_path": "/home/u"}),
            entry("repo_state.upload.enqueued", {"gcs_path": "b/before_codebase/1", "size_bytes": 10}),
        ]
        uploads, telemetry = gec.analyze_uploads(entries)
        assert len(uploads) == 1 and uploads[0]["status"] == "confirmed"
        assert len(telemetry) == 1
