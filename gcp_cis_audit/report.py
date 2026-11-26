"""Export audit results as JSON, CSV or a self-contained HTML report."""
from __future__ import annotations

import csv
import html
import json
from datetime import datetime
from typing import List

from .models import Result, FAIL, ERROR, MANUAL, PASS, NA
from .runner import summarize

_ORDER = {FAIL: 0, ERROR: 1, MANUAL: 2, PASS: 3, NA: 4}
_COLORS = {PASS: "#1e8e3e", FAIL: "#d93025", ERROR: "#e37400", MANUAL: "#5f6368", NA: "#9aa0a6"}


def to_json(results: List[Result], path: str):
    doc = {"generated": datetime.now().isoformat(timespec="seconds"),
           "benchmark": "CIS Google Cloud Platform Foundation Benchmark",
           "summary": summarize(results),
           "results": [r.to_dict() for r in results]}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)


def _csv_safe(v: str) -> str:
    # Neutralise spreadsheet formula injection from resource names / messages.
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def to_csv(results: List[Result], path: str):
    cols = ["project", "check_id", "title", "section", "level", "severity", "status", "message",
            "resources", "remediation"]
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for r in results:
            d = r.to_dict()
            d["resources"] = "; ".join(r.resources)
            w.writerow([_csv_safe(str(d[c])) for c in cols])


def to_html(results: List[Result], path: str):
    e = html.escape
    s = summarize(results)
    score = "n/a" if s["score"] is None else f"{s['score']}%"
    rows = []
    for r in sorted(results, key=lambda r: (r.project, _ORDER[r.status],
                                            tuple(int(p) for p in r.check_id.split(".")))):
        res = "".join(f"<li>{e(x)}</li>" for x in r.resources)
        rows.append(
            f"<tr class='{r.status.replace('/', '')}'><td>{e(r.project)}</td><td>{e(r.check_id)}</td>"
            f"<td>{e(r.title)}<details><summary>Details &amp; remediation</summary>"
            f"<p>{e(r.description)}</p><p><b>Remediation:</b> {e(r.remediation)}</p>"
            f"{'<p><b>Affected:</b></p><ul>' + res + '</ul>' if res else ''}</details></td>"
            f"<td>{e(r.severity)}</td><td style='color:{_COLORS[r.status]};font-weight:600'>{e(r.status)}</td>"
            f"<td>{e(r.message)}</td></tr>")
    chips = "".join(f"<span class='chip' style='background:{_COLORS[k]}'>{k}: {v}</span>"
                    for k, v in s["counts"].items())
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>CIS GCP Audit Report</title><style>
body{{font:14px system-ui,sans-serif;margin:2rem;color:#202124}}
h1{{margin-bottom:.2rem}} .chip{{color:#fff;padding:2px 10px;border-radius:12px;margin-right:6px}}
table{{border-collapse:collapse;width:100%;margin-top:1rem}}
th,td{{border:1px solid #dadce0;padding:6px 8px;text-align:left;vertical-align:top}}
th{{background:#f1f3f4}} details{{margin-top:4px;color:#5f6368}} summary{{cursor:pointer}}
</style></head><body>
<h1>CIS GCP Foundation Benchmark - Audit Report</h1>
<p>Generated {e(datetime.now().strftime('%Y-%m-%d %H:%M'))} &middot; Compliance score (PASS / (PASS+FAIL)): <b>{score}</b></p>
<p>{chips}</p>
<table><tr><th>Project</th><th>ID</th><th>Recommendation</th><th>Severity</th><th>Status</th><th>Result</th></tr>
{''.join(rows)}</table></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
