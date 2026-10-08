"""Unit tests for durable per-scan engine logging."""

import sys

from app.config import settings
from app.services import scan_log


def test_log_persists_to_disk_and_survives_memory_clear(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "scan_logs_dir", str(tmp_path / "logs"))
    scan_id = "scan-persist-1"

    scan_log.reset(scan_id)
    scan_log.log(scan_id, "hello from runner")
    scan_log.log(scan_id, "second line")

    path = scan_log._log_path(scan_id)
    assert path.is_file()
    assert "hello from runner" in path.read_text(encoding="utf-8")

    # Simulate memory eviction / process restart: drop in-memory buffers.
    with scan_log._lock:
        scan_log._buffers.clear()
        scan_log._next_seq.clear()

    lines, next_after = scan_log.get_logs(scan_id, after=0)
    assert next_after == 2
    assert [row["line"] for row in lines] == ["hello from runner", "second line"]

    only_second, _ = scan_log.get_logs(scan_id, after=1)
    assert [row["line"] for row in only_second] == ["second line"]


def test_capture_routes_print_into_scan_log(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "scan_logs_dir", str(tmp_path / "logs"))
    scan_id = "scan-print-1"
    scan_log.reset(scan_id)

    with scan_log.capture(scan_id):
        print("STEP 1 - from print()")

    lines, _ = scan_log.get_logs(scan_id, after=0)
    assert any("STEP 1 - from print()" in row["line"] for row in lines)


def test_reset_clears_previous_scan_history(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "scan_logs_dir", str(tmp_path / "logs"))
    scan_id = "scan-reset-1"
    scan_log.reset(scan_id)
    scan_log.log(scan_id, "old line")
    scan_log.reset(scan_id)
    scan_log.log(scan_id, "new line")

    lines, next_after = scan_log.get_logs(scan_id, after=0)
    assert next_after == 1
    assert [row["line"] for row in lines] == ["new line"]


def test_tee_stdout_does_not_crash_on_cp1252_box_drawing(tmp_path, monkeypatch):
    """Windows charmap (cp1252) cannot encode ├──; that used to abort the scan."""
    monkeypatch.setattr(settings, "scan_logs_dir", str(tmp_path / "logs"))
    scan_id = "scan-unicode-tree"
    scan_log.reset(scan_id)

    class Cp1252Stream:
        encoding = "cp1252"

        def write(self, data: str) -> int:
            data.encode("cp1252")
            return len(data)

        def flush(self) -> None:
            pass

        def isatty(self) -> bool:
            return False

    tee = scan_log._TeeStdout(Cp1252Stream())
    previous = getattr(scan_log._thread_local, "scan_id", None)
    scan_log._thread_local.scan_id = scan_id
    monkeypatch.setattr(sys, "stdout", tee)
    try:
        print(" " * 34 + "├── pom.xml")
    finally:
        scan_log._thread_local.scan_id = previous

    lines, _ = scan_log.get_logs(scan_id, after=0)
    assert any("├── pom.xml" in row["line"] for row in lines)
