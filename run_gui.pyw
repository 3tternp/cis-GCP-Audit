"""Double-click launcher: opens the GUI without a console window (use run_gui_demo.pyw for sample data)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gcp_cis_audit.gui import main

if __name__ == "__main__":
    main()
