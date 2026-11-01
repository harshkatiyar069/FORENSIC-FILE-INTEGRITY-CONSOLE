import hashlib
import os

import pytest

from fim.hasher import hash_file, hash_file_safe


def test_known_vector_abc(tmp_path):
    f = tmp_path / "abc.txt"
    f.write_bytes(b"abc")
    assert hash_file(f) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_empty_file_hash(tmp_path):
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    assert hash_file(f) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_large_file_matches_hashlib_with_small_chunks(tmp_path):
    data = os.urandom(3 * 1024 * 1024 + 17)  # about 3 MB, not a multiple of the chunk size
    f = tmp_path / "large.bin"
    f.write_bytes(data)
    assert hash_file(f, chunk_size=4096) == hashlib.sha256(data).hexdigest()


def test_identical_content_gives_identical_hash(tmp_path):
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_bytes(b"same content")
    b.write_bytes(b"same content")
    assert hash_file(a) == hash_file(b)


def test_one_byte_change_changes_hash(tmp_path):
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_bytes(b"hello world")
    b.write_bytes(b"hello worle")
    assert hash_file(a) != hash_file(b)


def test_invalid_chunk_size_raises(tmp_path):
    f = tmp_path / "x.txt"
    f.write_bytes(b"x")
    with pytest.raises(ValueError):
        hash_file(f, chunk_size=0)


def test_missing_file_is_reported_not_raised(tmp_path):
    digest, error = hash_file_safe(tmp_path / "does_not_exist.txt")
    assert digest is None
    assert error is not None