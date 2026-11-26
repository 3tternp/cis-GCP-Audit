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
    ap.add_argument("--web", action="store_true", help="serve the browser UI on localhost instead of the desktop GUI")
    ap.add_argument("--port", type=int, default=8765, help="port for --web (default 8765)")
    ap.add_argument("--no-browser", action="store_true", help="with --web: do not open a browser tab")
    ap.add_argument("--preflight", action="store_true",
                    help="with --cli: only test API access for the project(s), then exit")
    ap.add_argument("--demo", action="store_true", help="use offline sample data (no GCP access)")
    ap.add_argument("-p", "--project", action="append", default=[], help="project ID (repeatable)")
    ap.add_argument("--all-projects", action="store_true", help="audit every accessible project")
    ap.add_argument("--key-file", help="service account JSON key (default: Application Default Credentials)")
    ap.add_argument("--level", type=int, choices=(1, 2), default=2)
    ap.add_argument("--json"), ap.add_argument("--csv"), ap.add_argument("--html")
    a = ap.parse_args(argv)

    if a.web and not a.cli:
        from .webui import serve
        serve(port=a.port, demo=a.demo, open_browser=not a.no_browser)
        return 0

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

    if a.preflight:
        from .preflight import run_preflight
        bad = 0
        for p in projects:
            print(f"\nAPI access preflight for {p}")
            for row in run_preflight(client, p):
                bad += row["status"] not in ("OK", "API disabled")
                note = "" if row["status"] == "OK" else f"  <- needs {row['needs']}"
                print(f"  {row['status']:<18} {row['api']}{note}")
        return 1 if bad else 0

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
