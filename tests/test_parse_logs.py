"""Unit tests for parse_logs."""

import json

import pytest


def _write_lines(path, lines):
    path.write_text("\n".join(lines), encoding="utf-8")


class TestParseLogs:
    def test_missing_file_returns_empty(self, gec, tmp_path):
        assert gec.parse_logs(tmp_path / "does-not-exist.jsonl") == []

    def test_parses_valid_json_lines(self, gec, tmp_path):
        log = tmp_path / "unified.jsonl"
        _write_lines(log, [
            json.dumps({"msg": "a", "n": 1}),
            json.dumps({"msg": "b", "n": 2}),
        ])
        entries = gec.parse_logs(log)
        assert entries == [{"msg": "a", "n": 1}, {"msg": "b", "n": 2}]

    def test_skips_blank_lines(self, gec, tmp_path):
        log = tmp_path / "unified.jsonl"
        _write_lines(log, [
            json.dumps({"msg": "a"}),
            "",
            "   ",
            json.dumps({"msg": "b"}),
        ])
        entries = gec.parse_logs(log)
        assert [e["msg"] for e in entries] == ["a", "b"]

    def test_skips_malformed_json(self, gec, tmp_path):
        log = tmp_path / "unified.jsonl"
        _write_lines(log, [
            json.dumps({"msg": "good"}),
            "{not valid json",
            "also not json",
            json.dumps({"msg": "good2"}),
        ])
        entries = gec.parse_logs(log)
        assert [e["msg"] for e in entries] == ["good", "good2"]

    def test_empty_file_returns_empty(self, gec, tmp_path):
        log = tmp_path / "unified.jsonl"
        log.write_text("", encoding="utf-8")
        assert gec.parse_logs(log) == []

    def test_unreadable_log_raises(self, gec, tmp_path, monkeypatch):
        # A log that exists but cannot be read MUST NOT be silently treated as
        # "no activity" — that would yield a false GREEN. parse_logs surfaces
        # the error so main() can fail loudly instead.
        log = tmp_path / "unified.jsonl"
        log.write_text(json.dumps({"msg": "x"}), encoding="utf-8")

        def boom(*args, **kwargs):
            raise PermissionError("nope")

        monkeypatch.setattr("builtins.open", boom)
        with pytest.raises(OSError):
            gec.parse_logs(log)
