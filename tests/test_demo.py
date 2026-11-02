from fim.demo import run_demo


def test_demo_runs_end_to_end(tmp_path):
    lines: list[str] = []
    result = run_demo(tmp_path / "demo", say=lines.append)

    assert result.clean_scan_changes == 0
    assert result.changes == {"modified": 1, "deleted": 1, "new": 1, "renamed": 1}
    assert len(result.reports) == 3
    assert result.log_valid_before_attack
    assert result.tamper_detected
    assert any("Log integrity: FAILED" in line for line in lines)
