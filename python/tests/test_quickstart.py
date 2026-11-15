# The Python quick start in python/README.md. Test key material only.
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "test" / "vectors"
PYTHON_DIR = ROOT / "python"


def run(record):
    env = dict(os.environ, PYTHONPATH=str(PYTHON_DIR))
    proc = subprocess.run(
        [sys.executable, "-m", "parmana_verifier", str(VECTORS / record), str(VECTORS / "trust-python-ed25519.json")],
        capture_output=True, text=True, env=env, cwd=str(PYTHON_DIR),
    )
    return proc.returncode, json.loads(proc.stdout)


def test_quick_start_record_verifies():
    code, result = run("record-python-ed25519.json")
    assert code == 0
    assert result["valid"] is True
    assert result["coverage"] == "legacy"
    assert result["errors"] == []


def test_tampered_quick_start_record_is_refused():
    code, result = run("record-python-ed25519-tampered.json")
    assert code == 1
    assert result["valid"] is False
