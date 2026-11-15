# Verifies records produced by parmana-core, through the Python CLI. The expectations are in
# test/vectors/parmana-core-generated/cases.json, which the Node suite reads too. Test key material only.
import copy
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "test" / "vectors" / "parmana-core-generated"
PYTHON_DIR = ROOT / "python"
CASES = json.loads((FIXTURES / "cases.json").read_text())["cases"]
NODE = os.environ.get("PARMANA_NODE") or shutil.which("node")


def set_path(obj, path, value):
    keys = path.split(".")
    node = obj
    for key in keys[:-1]:
        node = node[int(key)] if isinstance(node, list) else node[key]
    last = keys[-1]
    if isinstance(node, list):
        node[int(last)] = value
    else:
        node[last] = value


def apply_trust_edits(trust, edits):
    keys = trust["keys"]
    for edit in edits or []:
        if "remove" in edit:
            keys = [key for key in keys if key["keyId"] != edit["remove"]]
        else:
            for key in keys:
                if key["keyId"] == edit["keyId"]:
                    key.update(edit["set"])
    return {**trust, "keys": keys}


def materialize(spec):
    record = json.loads((FIXTURES / spec["record"]).read_text())
    for op in spec.get("tamper", []):
        set_path(record, op["path"], op["value"])
    trust = apply_trust_edits(json.loads((FIXTURES / spec["trust"]).read_text()), spec.get("trustEdits"))
    return record, trust


def write_inputs(record, trust, tmp_path, label):
    record_path = tmp_path / f"{label}-record.json"
    trust_path = tmp_path / f"{label}-trust.json"
    record_path.write_text(json.dumps(record))
    trust_path.write_text(json.dumps(trust))
    return record_path, trust_path


def run_python(record, trust, tmp_path, label):
    record_path, trust_path = write_inputs(record, trust, tmp_path, label)
    env = dict(os.environ, PYTHONPATH=str(PYTHON_DIR))
    proc = subprocess.run(
        [sys.executable, "-m", "parmana_verifier", str(record_path), str(trust_path)],
        capture_output=True, text=True, env=env, cwd=str(PYTHON_DIR),
    )
    return proc.returncode, json.loads(proc.stdout)


def run_node(record, trust, tmp_path, label):
    record_path, trust_path = write_inputs(record, trust, tmp_path, label)
    proc = subprocess.run(
        [NODE, str(ROOT / "bin" / "parmana-verify.mjs"), str(record_path), str(trust_path)],
        capture_output=True, text=True,
    )
    return proc.returncode, json.loads(proc.stdout)


CASE_IDS = [case["name"] for case in CASES]


@pytest.mark.parametrize("spec", CASES, ids=CASE_IDS)
def test_python_verifier_matches_expectation(spec, tmp_path):
    record, trust = materialize(spec)
    exit_code, result = run_python(record, trust, tmp_path, "case")
    expect = spec["expect"]

    assert result["valid"] is expect["valid"], result["errors"]
    assert exit_code == (0 if expect["valid"] else 1)
    assert result["coverage"] == expect["coverage"]
    for check, value in expect.get("checks", {}).items():
        assert result["checks"].get(check) is value, (check, result["checks"])
    if "correspondence" in expect:
        assert result["correspondence"]["status"] == expect["correspondence"]
    if "errorIncludes" in expect:
        assert any(expect["errorIncludes"] in error for error in result["errors"]), result["errors"]
    if expect["valid"]:
        assert result["errors"] == []


@pytest.mark.skipif(NODE is None, reason="node is not on PATH; set PARMANA_NODE to a Node 24 binary")
@pytest.mark.parametrize("spec", CASES, ids=CASE_IDS)
def test_node_and_python_agree(spec, tmp_path):
    record, trust = materialize(spec)
    py_exit, py = run_python(copy.deepcopy(record), copy.deepcopy(trust), tmp_path, "py")
    node_exit, node = run_node(copy.deepcopy(record), copy.deepcopy(trust), tmp_path, "node")

    assert py_exit == node_exit
    assert py["valid"] == node["valid"]
    assert py["coverage"] == node["coverage"]
    assert py["checks"] == node["checks"]
    assert py["correspondence"] == node["correspondence"]
    assert len(py["errors"]) == len(node["errors"])
