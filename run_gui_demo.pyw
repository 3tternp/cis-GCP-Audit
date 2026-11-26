"""Double-click launcher: opens the GUI in Demo mode (offline sample data, no GCP credentials needed)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gcp_cis_audit.gui import main

if __name__ == "__main__":
    main(demo=True)
