# CIS GCP Audit Tool

A read-only Python GUI (Tkinter) that audits Google Cloud projects against the
**CIS Google Cloud Platform Foundation Benchmark**. It calls the GCP REST APIs directly and never changes anything.

## Run

```powershell
pip install -r requirements.txt
python -m gcp_cis_audit            # GUI
python -m gcp_cis_audit --demo     # GUI with offline sample data (no GCP needed)
python -m gcp_cis_audit --cli -p my-project --html report.html   # headless
python -m unittest discover -s tests
```

## Authentication
* **Application Default Credentials**: `gcloud auth application-default login`
* **Service account JSON key**
* **Access token**: `gcloud auth print-access-token` (held in memory only, never written to disk)

Grant the identity read-only roles: `roles/viewer`, `roles/iam.securityReviewer`,
`roles/cloudkms.viewer`, `roles/logging.viewer`, `roles/monitoring.viewer`, `roles/serviceusage.serviceUsageViewer`.
APIs that are disabled in a project show as **N/A**; missing permissions show as **ERROR**.

## Coverage (91 checks)
| Section | Checks |
|---|---|
| 1 IAM | 1.1 1.4 1.5 1.6 1.7 1.9 1.10, API keys 1.12-1.15 (+ manual 1.2 1.3 1.8) |
| 2 Logging | 2.1 2.2 2.3 2.4-2.11 (metric filter **and** alert) 2.13 |
| 3 Networking | 3.1-3.8 |
| 4 VMs | 4.1-4.6 4.8 4.9 (+ manual 4.7) |
| 5 Storage | 5.1 5.2 |
| 6 Cloud SQL | 6.4-6.7, MySQL flags 6.1.2-6.1.3, PostgreSQL flags 6.2.1-6.2.3 6.2.7-6.2.8, SQL Server flags 6.3.1-6.3.7 |
| 7 BigQuery | 7.1 7.3 |
| 8 GKE | 8.1-8.13 (private nodes, authorized networks, network policy, ABAC, logging, Workload Identity, ...) |
| 9 Dataproc | 9.1-9.2 |
| 10 Organization Policy | 10.1-10.11 - effective org-policy constraints enforced on the project |

Hierarchy awareness: checks 2.1 (audit config) and 2.2 (catch-all sink) also evaluate organization/folder
audit configs and aggregated sinks. If an ancestor can't be read with your credentials, the finding says
"Not evaluated: ..." rather than silently passing or failing.

## Limits to know about
* Sections 8-10 and API-key checks are extras beyond the core CIS GCP v3.0.0 numbering; their IDs are this tool's own.
* Other org-level resources (org-wide IAM review, org-level log metrics) are not audited - the scope is per project
  plus inherited audit config, sinks and org policy.
* Numbering follows CIS GCP v3.0.0 on a best-effort basis; verify against your licensed benchmark copy.
* Extra permissions for the new areas: `roles/container.viewer`, `roles/dataproc.viewer`,
  `roles/cloudsql.viewer`, `roles/serviceusage.apiKeysViewer`, `roles/orgpolicy.policyViewer`, and
  `roles/resourcemanager.organizationViewer` / `folderViewer` plus `roles/iam.securityReviewer` on the org/folders
  (needed to read inherited audit config).
* Score = PASS / (PASS + FAIL). MANUAL, N/A and ERROR are excluded.

## Adding a check
Add a function in `gcp_cis_audit/checks.py` with the `@check(...)` decorator. Use `ctx.<helper>()` for cached
API data and return `passed()`, `failed(msg, resources)` or `evaluate(total, bad, noun)`.
