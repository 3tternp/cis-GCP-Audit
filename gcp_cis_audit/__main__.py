"""Entry point: GUI by default, ``--cli`` for headless runs.

  python -m gcp_cis_audit                       # GUI
  python -m gcp_cis_audit --demo                # GUI with offline sample data
  python -m gcp_cis_audit --cli -p my-proj --html out.html
"""
import argparse
import sys

from . import report
from .runner import run_audit, select_checks, summarize


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gcp_cis_audit", description="CIS GCP configuration audit (read-only)")
    ap.add_argument("--cli", action="store_true", help="run headless instead of opening the GUI")
    ap.add_argument("--demo", action="store_true", help="use offline sample data (no GCP access)")
    ap.add_argument("-p", "--project", action="append", default=[], help="project ID (repeatable)")
    ap.add_argument("--all-projects", action="store_true", help="audit every accessible project")
    ap.add_argument("--key-file", help="service account JSON key (default: Application Default Credentials)")
    ap.add_argument("--level", type=int, choices=(1, 2), default=2)
    ap.add_argument("--json"), ap.add_argument("--csv"), ap.add_argument("--html")
    a = ap.parse_args(argv)

    if not a.cli:
        from .gui import main as gui_main
        gui_main(demo=a.demo)
        return 0

    if a.demo:
        from .demo import DemoClient
        client = DemoClient()
    else:
        from .client import GcpClient
        client = GcpClient("key" if a.key_file else "adc", a.key_file or "")
    projects = a.project or (client.discover_projects() if a.all_projects or a.demo else [])
    if not projects:
        ap.error("specify -p PROJECT or --all-projects")

    def show(r, done, total):
        print(f"[{done}/{total}] {r.project:<20} {r.check_id:<6} {r.status:<7} {r.title}")

    results = run_audit(client, projects, select_checks(max_level=a.level), show)
    s = summarize(results)
    print(f"\nScore: {s['score']}%  {s['counts']}")
    for flag, fn in ((a.json, report.to_json), (a.csv, report.to_csv), (a.html, report.to_html)):
        if flag:
            fn(results, flag)
            print("Wrote", flag)
    return 1 if s["counts"]["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
