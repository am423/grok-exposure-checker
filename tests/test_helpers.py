"""Unit tests for the small helper functions: fmt_bytes, esc, get_grok_home."""

from pathlib import Path

import pytest


class TestFmtBytes:
    def test_none_returns_unknown(self, gec):
        assert gec.fmt_bytes(None) == "unknown"

    def test_zero_bytes(self, gec):
        assert gec.fmt_bytes(0) == "0 B"

    def test_bytes_use_integer_format(self, gec):
        # Sub-KB values render with no decimals and a "B" unit.
        assert gec.fmt_bytes(512) == "512 B"
        assert gec.fmt_bytes(1023) == "1023 B"

    def test_kilobytes_use_one_decimal(self, gec):
        assert gec.fmt_bytes(1024) == "1.0 KB"
        assert gec.fmt_bytes(1536) == "1.5 KB"

    def test_megabytes(self, gec):
        assert gec.fmt_bytes(5 * 1024 * 1024) == "5.0 MB"

    def test_gigabytes(self, gec):
        assert gec.fmt_bytes(3 * 1024 ** 3) == "3.0 GB"

    def test_terabytes_is_largest_unit(self, gec):
        assert gec.fmt_bytes(2 * 1024 ** 4) == "2.0 TB"

    def test_petabyte_still_reported_in_tb(self, gec):
        # There is no PB unit, so very large values stay in TB.
        assert gec.fmt_bytes(1024 ** 5).endswith(" TB")


class TestEsc:
    def test_escapes_angle_brackets(self, gec):
        assert gec.esc("<script>") == "&lt;script&gt;"

    def test_escapes_ampersand(self, gec):
        assert gec.esc("a & b") == "a &amp; b"

    def test_escapes_quotes(self, gec):
        assert gec.esc('"x"') == "&quot;x&quot;"
        assert gec.esc("'y'") == "&#x27;y&#x27;"

    def test_coerces_non_string(self, gec):
        assert gec.esc(123) == "123"

    def test_plain_text_unchanged(self, gec):
        assert gec.esc("hello world") == "hello world"


class TestGetGrokHome:
    def test_respects_grok_home_env(self, gec, monkeypatch, tmp_path):
        custom = tmp_path / "custom-grok"
        monkeypatch.setenv("GROK_HOME", str(custom))
        assert gec.get_grok_home() == Path(str(custom))

    def test_defaults_to_home_dot_grok(self, gec, monkeypatch, tmp_path):
        monkeypatch.delenv("GROK_HOME", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path))
        assert gec.get_grok_home() == tmp_path / ".grok"

    def test_empty_grok_home_falls_back_to_default(self, gec, monkeypatch, tmp_path):
        # An empty string is falsy, so the default path is used.
        monkeypatch.setenv("GROK_HOME", "")
        monkeypatch.setenv("HOME", str(tmp_path))
        assert gec.get_grok_home() == tmp_path / ".grok"
