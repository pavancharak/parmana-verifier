# The quick start in python/README.md runs a schema version 3 single-mode record through the CLI. Test key material only.
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "test" / "vectors" / "parmana-core-generated"
PYTHON_DIR = ROOT / "python"


def run(record_path):
    env = dict(os.environ, PYTHONPATH=str(PYTHON_DIR))
    proc = subprocess.run(
        [sys.executable, "-m", "parmana_verifier", str(record_path), str(FIXTURES / "trust-v3-single.json")],
        capture_output=True, text=True, env=env, cwd=str(PYTHON_DIR),
    )
    return proc.returncode, json.loads(proc.stdout)


def test_quick_start_record_verifies():
    code, result = run(FIXTURES / "v3-single-record.json")
    assert code == 0
    assert result["valid"] is True
    assert result["errors"] == []


def test_tampered_quick_start_record_is_refused(tmp_path):
    record = json.loads((FIXTURES / "v3-single-record.json").read_text(encoding="utf-8"))
    record["transaction"]["signals"]["amount"] = 999
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    code, result = run(path)
    assert code == 1
    assert result["valid"] is False
