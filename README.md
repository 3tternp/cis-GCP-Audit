<p align="center">
  <img src="assets/icon.png" alt="CIS GCP Audit shield logo" width="120">
</p>

<h1 align="center">CIS GCP Audit Tool</h1>

<p align="center">
  <a href="https://github.com/3tternp/cis-GCP-Audit/actions/workflows/ci.yml"><img src="https://github.com/3tternp/cis-GCP-Audit/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/GUI-Tkinter-4285F4" alt="Tkinter GUI">
  <img src="https://img.shields.io/badge/checks-91-1e8e3e" alt="91 checks">
  <img src="https://img.shields.io/badge/access-read--only-5f6368" alt="Read-only">
</p>

<p align="center">
  A <b>read-only</b> Python GUI that audits Google Cloud projects against the
  <b>CIS Google Cloud Platform Foundation Benchmark</b>.<br>
  It calls the GCP REST APIs directly and never changes anything.
</p>

<p align="center">
  <img src="docs/screenshot.png" alt="Screenshot of the CIS GCP Audit GUI showing failed checks with a detail pane" width="900">
</p>

## ✨ Features

- 🖥️ **Desktop GUI** (Tkinter, no extra UI dependencies) plus a headless **CLI**
- 🔐 **Three sign-in options**: Application Default Credentials, service account key, or access token
- 🔎 **Project discovery**: list every project your credential can see, or add IDs manually
- 🧪 **91 checks** across 10 sections, with rationale and remediation for every finding
- 🏢 **Hierarchy aware**: audit config and log sinks inherited from folders and the organization
- 📊 **Compliance score**, sortable table and status filter
- 📤 **Export** to HTML, CSV or JSON
- 🎭 **Demo mode**: try everything offline with sample data, no GCP account needed
- ✅ **Tested**: 23 unit tests run in CI on Windows and Linux

## 🚀 Quick start

```powershell
pip install -r requirements.txt
python -m gcp_cis_audit            # opens the GUI
```

| I want to... | Do this |
|---|---|
| 🖱️ Open the GUI by double-clicking | Double-click `run_gui.pyw` |
| 🎭 Try it with sample data | Double-click `run_gui_demo.pyw`, or `python -m gcp_cis_audit --demo` |
| ⌨️ Run headless / in a pipeline | `python -m gcp_cis_audit --cli -p my-project --html report.html` |
| 🧪 Run the tests | `python -m unittest discover -s tests` |

The CLI exits with code `1` when any check fails, so it can gate a pipeline.

## 🔑 Authentication

| Method | How |
|---|---|
| 🪪 Application Default Credentials | `gcloud auth application-default login` |
| 🗝️ Service account key | Pick the JSON key file in the GUI (or `--key-file`) |
| 🎟️ Access token | Paste the output of `gcloud auth print-access-token` (kept in memory only, never written to disk) |

Grant the identity read-only roles: `roles/viewer`, `roles/iam.securityReviewer`, `roles/cloudkms.viewer`,
`roles/logging.viewer`, `roles/monitoring.viewer`, `roles/serviceusage.serviceUsageViewer`.
APIs that are disabled in a project show as **N/A**; missing permissions show as **ERROR**.

## 📋 Coverage (91 checks)

| | Section | Checks |
|---|---|---|
| 👤 | **1 IAM** | 1.1 1.4 1.5 1.6 1.7 1.9 1.10, API keys 1.12-1.15 (+ manual 1.2 1.3 1.8) |
| 📜 | **2 Logging & Monitoring** | 2.1 2.2 2.3, 2.4-2.11 (metric filter **and** alert), 2.13 |
| 🌐 | **3 Networking** | 3.1-3.8 (default/legacy networks, DNSSEC, SSH/RDP exposure, flow logs) |
| 💻 | **4 Virtual Machines** | 4.1-4.6 4.8 4.9 (+ manual 4.7) |
| 🪣 | **5 Storage** | 5.1 5.2 |
| 🗄️ | **6 Cloud SQL** | 6.4-6.7, MySQL flags 6.1.2-6.1.3, PostgreSQL flags 6.2.x, SQL Server flags 6.3.1-6.3.7 |
| 📈 | **7 BigQuery** | 7.1 7.3 |
| ☸️ | **8 GKE** | 8.1-8.13 (private nodes, authorized networks, network policy, ABAC, Workload Identity, ...) |
| ⚙️ | **9 Dataproc** | 9.1-9.2 |
| 🏛️ | **10 Organization Policy** | 10.1-10.11 (effective org-policy constraints enforced on the project) |

**Hierarchy awareness:** checks 2.1 (audit config) and 2.2 (catch-all sink) also evaluate organization and
folder audit configs and aggregated sinks. If an ancestor can't be read with your credentials, the finding says
"Not evaluated: ..." instead of silently passing or failing.

## 🚦 Result statuses

| Status | Meaning |
|---|---|
| 🟢 **PASS** | Compliant |
| 🔴 **FAIL** | Non-compliant; affected resources and remediation are shown |
| 🟠 **ERROR** | The check could not run (usually missing permission) |
| ⚪ **MANUAL** | Cannot be assessed through the API; verify by hand |
| ⚫ **N/A** | Nothing to audit (API disabled or no such resources) |

Score = PASS / (PASS + FAIL). MANUAL, N/A and ERROR are excluded.

## ⚠️ Limits to know about

- Sections 8-10 and the API-key checks go beyond the core CIS GCP v3.0.0 numbering; their IDs are this tool's own.
- Scope is per project plus inherited audit config, sinks and org policy. Org-wide IAM review and org-level
  log metrics are not audited.
- Numbering follows CIS GCP v3.0.0 on a best-effort basis; verify against your licensed benchmark copy.
- Extra read permissions for the newer areas: `roles/container.viewer`, `roles/dataproc.viewer`,
  `roles/cloudsql.viewer`, `roles/serviceusage.apiKeysViewer`, `roles/orgpolicy.policyViewer`, and
  `roles/resourcemanager.organizationViewer` / `folderViewer` plus `roles/iam.securityReviewer` on the org and
  folders (needed to read inherited audit config).
- The tool has been tested against the bundled demo data and stub clients, not a live GCP environment.

## 🧩 Adding a check

Add a function in `gcp_cis_audit/checks.py` (or `checks_extra.py`) with the `@check(...)` decorator. Use
`ctx.<helper>()` for cached API data and return `passed()`, `failed(msg, resources)` or
`evaluate(total, bad, noun)`.

## 🗂️ Project layout

```
gcp_cis_audit/   checks.py, checks_extra.py, client.py, runner.py, report.py, gui.py, demo.py
tests/           unit tests (run in CI)
assets/          app icon          docs/   README screenshot
run_gui.pyw      double-click launcher        run_gui_demo.pyw   launcher with sample data
```
