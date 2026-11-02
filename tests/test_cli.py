import sqlite3

import pytest

from app import main as app_main
from fim.baseline import BASELINE_UPDATE_PHRASE
from fim.config import Settings


@pytest.fixture
def cli(tmp_path, monkeypatch):
    src = tmp_path / "watched"
    src.mkdir()
    (src / "a.txt").write_text("a")
    settings = Settings(db_path=tmp_path / "data" / "fim.db", report_dir=tmp_path / "reports")
    monkeypatch.setattr(app_main, "DEFAULT_SETTINGS", settings)
    return src, settings


def test_full_cli_flow(cli, capsys):
    src, settings = cli
    assert app_main.main(["init", str(src)]) == 0
    (src / "a.txt").write_text("changed")
    assert app_main.main(["scan"]) == 0
    assert app_main.main(["report", "--format", "csv"]) == 0
    assert app_main.main(["verify-log"]) == 0

    out = capsys.readouterr().out
    assert "Modified      : 1" in out
    assert list(settings.report_dir.glob("*.csv"))


def test_verify_log_fails_after_tampering(cli):
    src, settings = cli
    app_main.main(["init", str(src)])

    raw = sqlite3.connect(settings.db_path)
    raw.execute("DROP TRIGGER security_events_no_update")
    raw.execute("UPDATE security_events SET details = '{}' WHERE id = 1")
    raw.commit()
    raw.close()

    assert app_main.main(["verify-log"]) == 2


def test_scan_without_baseline_returns_error(cli):
    assert app_main.main(["scan"]) == 1


def test_update_baseline_requires_exact_phrase(cli):
    src, _ = cli
    app_main.main(["init", str(src)])
    assert app_main.main(["update-baseline"]) == 1
    assert app_main.main(["update-baseline", "--confirm", "yes"]) == 1
    assert app_main.main(["update-baseline", "--confirm", BASELINE_UPDATE_PHRASE]) == 0

