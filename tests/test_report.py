"""Tests for the results-table builder (owner: Rajbeer)."""

import csv
import json

from eval.report import load_results, to_csv, to_markdown


def write_result(path, **kw):
    path.write_text(json.dumps(kw))
    return path


def test_loads_and_infers_detector_attack_from_filename(tmp_path):
    p = write_result(tmp_path / "kitsune_synscan.json", roc_auc=0.98, tpr_at_threshold=0.95)
    res = load_results([p])
    assert res[0]["detector"] == "kitsune" and res[0]["attack"] == "synscan"


def test_explicit_keys_win_over_filename(tmp_path):
    p = write_result(tmp_path / "x.json", detector="rules", attack="arpspoof", roc_auc=0.9)
    assert load_results([p])[0]["detector"] == "rules"


def test_markdown_table_has_header_and_rows(tmp_path):
    results = [
        {"detector": "kitsune", "attack": "synscan", "roc_auc": 0.98, "tpr_at_threshold": 0.95,
         "fpr_at_threshold": 0.01, "detected_runs": 3, "median_time_to_detect_s": 1.2,
         "false_alerts_per_hour": 0.5},
        {"detector": "rules", "attack": "synscan", "roc_auc": 0.80, "tpr_at_threshold": 0.7,
         "fpr_at_threshold": 0.05, "detected_runs": 2, "median_time_to_detect_s": 3.0,
         "false_alerts_per_hour": 2.0},
    ]
    md = to_markdown(results)
    lines = md.splitlines()
    assert lines[0].startswith("| Detector | Attack |")
    assert "| kitsune | synscan |" in md
    assert len([x for x in lines if x.startswith("|")]) == 4   # header + separator + 2 rows


def test_nan_and_missing_render_as_dash():
    md = to_markdown([{"detector": "rf", "attack": "udpflood", "roc_auc": float("nan")}])
    row = md.splitlines()[-1]
    assert "| rf | udpflood |" in row and "-" in row


def test_csv_output(tmp_path):
    results = [{"detector": "kitsune", "attack": "arpspoof", "roc_auc": 0.97,
                "tpr_at_threshold": 0.9, "fpr_at_threshold": 0.0, "detected_runs": 3,
                "median_time_to_detect_s": 0.8, "false_alerts_per_hour": 0.2}]
    out = tmp_path / "t.csv"
    to_csv(results, out)
    rows = list(csv.reader(open(out)))
    assert rows[0][0] == "Detector"
    assert rows[1][0] == "kitsune" and rows[1][4] == "0.97"


def test_sorted_by_attack_then_detector():
    results = [
        {"detector": "rules", "attack": "synscan"},
        {"detector": "kitsune", "attack": "arpspoof"},
        {"detector": "kitsune", "attack": "synscan"},
    ]
    md = to_markdown(results)
    order = [ln for ln in md.splitlines()
             if ln.startswith("| ") and "Detector" not in ln and "---" not in ln]
    assert "arpspoof" in order[0]                 # arpspoof sorts before synscan
    assert "kitsune | synscan" in order[1] and "rules | synscan" in order[2]
