"""Preflight: probe every API the audit uses so permission/API problems show up before a full run."""
from __future__ import annotations

from typing import List

from .client import ApiError

OK, DISABLED, DENIED, ERROR = "OK", "API disabled", "Permission denied", "Error"


def _probes(p: str):
    gcp = "https://%s.googleapis.com"
    return [
        ("Resource Manager (IAM policy, hierarchy)", "POST",
         f"https://cloudresourcemanager.googleapis.com/v1/projects/{p}:getIamPolicy", None, "roles/iam.securityReviewer"),
        ("Resource Manager (ancestry)", "POST",
         f"https://cloudresourcemanager.googleapis.com/v1/projects/{p}:getAncestry", None,
         "resourcemanager.projects.get"),
        ("IAM (service accounts)", "GET", f"{gcp % 'iam'}/v1/projects/{p}/serviceAccounts", {"pageSize": 1},
         "roles/iam.securityReviewer"),
        ("Compute Engine", "GET", f"{gcp % 'compute'}/compute/v1/projects/{p}", None, "roles/compute.viewer"),
        ("Cloud Logging", "GET", f"{gcp % 'logging'}/v2/projects/{p}/sinks", {"pageSize": 1}, "roles/logging.viewer"),
        ("Cloud Monitoring", "GET", f"{gcp % 'monitoring'}/v3/projects/{p}/alertPolicies", {"pageSize": 1},
         "roles/monitoring.viewer"),
        ("Cloud Storage", "GET", f"{gcp % 'storage'}/storage/v1/b", {"project": p, "maxResults": 1},
         "roles/storage.admin or storage.buckets.list + getIamPolicy"),
        ("Cloud SQL", "GET", f"{gcp % 'sqladmin'}/v1/projects/{p}/instances", {"maxResults": 1}, "roles/cloudsql.viewer"),
        ("BigQuery", "GET", f"{gcp % 'bigquery'}/bigquery/v2/projects/{p}/datasets", {"maxResults": 1},
         "roles/bigquery.metadataViewer"),
        ("Cloud DNS", "GET", f"{gcp % 'dns'}/dns/v1/projects/{p}/managedZones", {"maxResults": 1}, "roles/dns.reader"),
        ("Cloud KMS", "GET", f"{gcp % 'cloudkms'}/v1/projects/{p}/locations", {"pageSize": 1}, "roles/cloudkms.viewer"),
        ("GKE", "GET", f"{gcp % 'container'}/v1/projects/{p}/locations/-/clusters", None, "roles/container.viewer"),
        ("Dataproc", "GET", f"{gcp % 'dataproc'}/v1/projects/{p}/regions/us-central1/clusters", {"pageSize": 1},
         "roles/dataproc.viewer"),
        ("API Keys", "GET", f"{gcp % 'apikeys'}/v2/projects/{p}/locations/global/keys", {"pageSize": 1},
         "roles/serviceusage.apiKeysViewer"),
        ("Service Usage", "GET", f"{gcp % 'serviceusage'}/v1/projects/{p}/services/cloudasset.googleapis.com", None,
         "roles/serviceusage.serviceUsageViewer"),
        ("Organization Policy", "GET",
         f"{gcp % 'orgpolicy'}/v2/projects/{p}/policies/compute.requireOsLogin:getEffectivePolicy", None,
         "roles/orgpolicy.policyViewer"),
    ]


def run_preflight(client, project: str) -> List[dict]:
    """One row per API: {api, status, detail, needs}.  Never raises."""
    rows = []
    for name, method, url, params, needs in _probes(project):
        try:
            if method == "POST":
                client.post(url, {})
            else:
                client.get(url, params)
            rows.append({"api": name, "status": OK, "detail": "", "needs": needs})
        except ApiError as exc:
            if exc.service_disabled:
                st = DISABLED
            elif exc.status == 403 or exc.status == 401:
                st = DENIED
            elif exc.status == 404:
                st = OK  # resource simply absent (e.g. no policy / region has nothing) - API reachable
            else:
                st = ERROR
            rows.append({"api": name, "status": st, "detail": exc.message[:160], "needs": needs})
        except Exception as exc:
            rows.append({"api": name, "status": ERROR, "detail": f"{type(exc).__name__}: {exc}"[:160],
                         "needs": needs})
    return rows
