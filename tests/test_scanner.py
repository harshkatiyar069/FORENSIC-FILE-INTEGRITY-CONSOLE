import os
from pathlib import Path

import pytest

from fim.scanner import scan_directory


def names(result):
    return {Path(r.path).name for r in result.records}


def test_finds_files_recursively(tmp_path):
    (tmp_path / "top.txt").write_text("1")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "deep.txt").write_text("2")

    result = scan_directory(tmp_path)
    assert names(result) == {"top.txt", "deep.txt"}


def test_records_have_hash_size_and_mtime(tmp_path):
    f = tmp_path / "data.txt"
    f.write_bytes(b"abc")

    result = scan_directory(tmp_path)
    record = result.records[0]
    assert record.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert record.size_bytes == 3
    assert record.mtime_ns > 0
    assert record.error is None
    assert record.unstable is False


def test_file_exclusion_pattern(tmp_path):
    (tmp_path / "keep.txt").write_text("k")
    (tmp_path / "debug.log").write_text("d")

    result = scan_directory(tmp_path, exclude_patterns=("*.log",))
    assert names(result) == {"keep.txt"}


def test_directory_exclusion_pattern(tmp_path):
    (tmp_path / "cache").mkdir()
    (tmp_path / "cache" / "junk.txt").write_text("j")
    (tmp_path / "real.txt").write_text("r")

    result = scan_directory(tmp_path, exclude_patterns=("cache",))
    assert names(result) == {"real.txt"}


def test_empty_file_is_included(tmp_path):
    (tmp_path / "empty.txt").write_bytes(b"")

    result = scan_directory(tmp_path)
    assert names(result) == {"empty.txt"}
    assert result.records[0].size_bytes == 0


def test_duplicate_contents_share_hash(tmp_path):
    (tmp_path / "one.txt").write_text("same")
    (tmp_path / "two.txt").write_text("same")

    result = scan_directory(tmp_path)
    hashes = {r.sha256 for r in result.records}
    assert len(hashes) == 1


def test_symlinks_are_skipped(tmp_path):
    real = tmp_path / "real.txt"
    real.write_text("x")
    link = tmp_path / "link.txt"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        pytest.skip("Creating symlinks on Windows needs Developer Mode or admin rights")

    result = scan_directory(tmp_path)
    assert names(result) == {"real.txt"}
    assert any("link.txt" in path for path, _ in result.skipped)


def test_nonexistent_root_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        scan_directory(tmp_path / "missing")


def test_file_as_root_raises(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("x")
    with pytest.raises(NotADirectoryError):
        scan_directory(f)


def test_metadata_only_mode_skips_hashing(tmp_path):
    (tmp_path / "a.txt").write_text("a")

    result = scan_directory(tmp_path, compute_hashes=False)
    assert result.records[0].sha256 is None