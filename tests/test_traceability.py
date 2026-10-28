"""GRC traceability: threat model <-> control mapping <-> evidence index stay consistent.

An auditor's first question is "show me the control for this risk, and the evidence for that
control". These tests make the repository answer it, and fail CI if the chain breaks (RA-3, CA-7).
"""
import csv
import re

from conftest import ROOT

COLUMNS = ["Control ID", "Control Name", "Implementation", "Validation", "Evidence ID", "Threat IDs", "Status"]


def controls():
    with open(ROOT / "controls" / "control-mapping.csv", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == COLUMNS, reader.fieldnames
        return list(reader)


def split(cell):
    return {x.strip() for x in cell.split(";") if x.strip()}


def threat_ids():
    text = (ROOT / "threat-model.md").read_text(encoding="utf-8")
    return set(re.findall(r"^\| (T\d{2}) \|", text, flags=re.M))


def evidence_ids():
    text = (ROOT / "evidence" / "README.md").read_text(encoding="utf-8")
    return set(re.findall(r"^\| (EVD-\d{3}) \|", text, flags=re.M))


def test_every_row_is_complete():
    for row in controls():
        empty = [c for c in COLUMNS if not row[c].strip()]
        assert not empty, f"{row['Control ID']} has empty {empty}"
        assert re.fullmatch(r"[A-Z]{2}-\d+(\(\d+\))?", row["Control ID"]), row["Control ID"]


def test_control_ids_are_unique():
    ids = [r["Control ID"] for r in controls()]
    assert len(ids) == len(set(ids))


def test_threat_model_defines_threats():
    assert len(threat_ids()) >= 10


def test_every_control_points_at_real_threats():
    known = threat_ids()
    for row in controls():
        unknown = split(row["Threat IDs"]) - known
        assert not unknown, f"{row['Control ID']} references undefined threats {unknown}"


def test_every_threat_has_at_least_one_control():
    covered = set().union(*(split(r["Threat IDs"]) for r in controls()))
    missing = threat_ids() - covered
    assert not missing, f"threats with no control: {sorted(missing)}"


def test_every_control_has_indexed_evidence():
    known = evidence_ids()
    for row in controls():
        unknown = split(row["Evidence ID"]) - known
        assert not unknown, f"{row['Control ID']} cites evidence not in evidence/README.md: {unknown}"


def test_core_zero_trust_controls_present():
    ids = {r["Control ID"] for r in controls()}
    for required in ("AC-3", "AC-6", "IA-5", "IA-5(7)", "IA-9", "AU-2", "SC-7", "SC-28"):
        assert required in ids, f"missing {required}"
