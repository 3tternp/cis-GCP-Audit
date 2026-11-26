"""CIS Google Cloud Platform Foundation Benchmark checks (project scope).

Recommendation numbering follows CIS GCP Foundation Benchmark v3.0.0 as closely
as possible; always confirm against your licensed copy of the benchmark.
All checks are strictly read-only.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Callable, Dict, List

from .client import ApiError
from .models import (Check, Outcome, MANUAL, evaluate, failed, not_applicable, passed)

REGISTRY: List[Check] = []

SEC_IAM = "1 - IAM"
SEC_LOG = "2 - Logging & Monitoring"
SEC_NET = "3 - Networking"
SEC_VM = "4 - Virtual Machines"
SEC_STO = "5 - Storage"
SEC_SQL = "6 - Cloud SQL"
SEC_BQ = "7 - BigQuery"
SEC_GKE = "8 - GKE"
SEC_DP = "9 - Dataproc"
SEC_OP = "10 - Organization Policy"
SEC_ORG = "11 - Organization level"
SECTIONS = [SEC_IAM, SEC_LOG, SEC_NET, SEC_VM, SEC_STO, SEC_SQL, SEC_BQ, SEC_GKE, SEC_DP, SEC_OP, SEC_ORG]


def check(cid, title, section, level, severity, description, remediation, scope="project"):
    def deco(fn: Callable) -> Callable:
        REGISTRY.append(Check(cid, title, section, level, severity, description, remediation, fn, scope))
        return fn
    return deco


def manual(cid, title, section, level, severity, description, remediation):
    REGISTRY.append(Check(cid, title, section, level, severity, description, remediation, None))


# --------------------------------------------------------------------------- #
# Context: per-project cache of API data so checks share a single fetch
# --------------------------------------------------------------------------- #
class Context:
    def __init__(self, client, project: str):
        self.c = client
        self.p = project
        self._cache: Dict[str, object] = {}

    def memo(self, key: str, fn: Callable):
        if key not in self._cache:
            try:
                self._cache[key] = ("ok", fn())
            except Exception as exc:  # cached so a failing API is called once
                self._cache[key] = ("err", exc)
        state, val = self._cache[key]
        if state == "err":
            raise val
        return val

    # IAM / Resource Manager
    def iam_policy(self) -> dict:
        return self.memo("iam", lambda: self.c.post(
            f"https://cloudresourcemanager.googleapis.com/v1/projects/{self.p}:getIamPolicy",
            {"options": {"requestedPolicyVersion": 3}}))

    # Hierarchy (folders / organization) - visibility depends on the caller's permissions
    def ancestors(self):
        """([(type, id)] for folder/organization ancestors, note-or-None)."""
        def load():
            try:
                data = self.c.post(
                    f"https://cloudresourcemanager.googleapis.com/v1/projects/{self.p}:getAncestry")
            except ApiError as exc:
                return [], f"Project hierarchy unreadable (HTTP {exc.status})"
            out = []
            for a in data.get("ancestor", []):
                r = a.get("resourceId", {})
                if r.get("type") in ("folder", "organization"):
                    out.append((r["type"], r["id"]))
            return out, None
        return self.memo("anc", load)

    @staticmethod
    def _plural(kind: str) -> str:
        return "organizations" if kind == "organization" else "folders"

    def inherited_policies(self):
        """([(label, iam_policy)] from ancestors, [notes about unreadable ones])."""
        def load():
            anc, note = self.ancestors()
            pols, notes = [], [note] if note else []
            for kind, ident in anc:
                try:
                    pols.append((f"{kind} {ident}", self.c.post(
                        f"https://cloudresourcemanager.googleapis.com/v3/{self._plural(kind)}/{ident}:getIamPolicy",
                        {"options": {"requestedPolicyVersion": 3}})))
                except ApiError as exc:
                    notes.append(f"{kind} {ident} IAM policy unreadable (HTTP {exc.status})")
            return pols, notes
        return self.memo("ipol", load)

    def inherited_sinks(self):
        """([(label, sink)] aggregated sinks with includeChildren, [notes])."""
        def load():
            anc, note = self.ancestors()
            out, notes = [], [note] if note else []
            for kind, ident in anc:
                try:
                    for s in self.c.list(f"https://logging.googleapis.com/v2/{self._plural(kind)}/{ident}/sinks",
                                         "sinks"):
                        if s.get("includeChildren"):
                            out.append((f"{kind} {ident}", s))
                except ApiError as exc:
                    notes.append(f"{kind} {ident} sinks unreadable (HTTP {exc.status})")
            return out, notes
        return self.memo("isinks", load)

    def effective_org_policy(self, constraint: str) -> dict:
        def load():
            try:
                return self.c.get(f"https://orgpolicy.googleapis.com/v2/projects/{self.p}"
                                  f"/policies/{constraint}:getEffectivePolicy")
            except ApiError as exc:
                if exc.status == 404:
                    return {}
                raise
        return self.memo("op:" + constraint, load)

    def api_keys(self) -> List[dict]:
        return self.memo("apikeys", lambda: self.c.list(
            f"https://apikeys.googleapis.com/v2/projects/{self.p}/locations/global/keys", "keys"))

    def gke_clusters(self) -> List[dict]:
        return self.memo("gke", lambda: self.c.get(
            f"https://container.googleapis.com/v1/projects/{self.p}/locations/-/clusters").get("clusters", []))

    def dataproc_clusters(self) -> List[dict]:
        def load():
            regions = self.c.list(
                f"https://compute.googleapis.com/compute/v1/projects/{self.p}/regions", "items")
            out = []
            for r in regions:
                out.extend(self.c.list(f"https://dataproc.googleapis.com/v1/projects/{self.p}"
                                       f"/regions/{r['name']}/clusters", "clusters"))
            return out
        return self.memo("dp", load)

    # Networking extras
    def dns_policies(self) -> List[dict]:
        def load():
            try:
                return self.c.list(f"https://dns.googleapis.com/dns/v1/projects/{self.p}/policies", "policies")
            except ApiError as exc:
                if exc.service_disabled:   # Cloud DNS off => no resolver logging can exist
                    return []
                raise
        return self.memo("dnspol", load)

    def backend_services(self) -> List[dict]:
        return self.memo("backends", lambda: self.c.agg_list(
            f"https://compute.googleapis.com/compute/v1/projects/{self.p}/aggregated/backendServices",
            "backendServices"))

    def tls_proxies(self) -> List[dict]:
        base = f"https://compute.googleapis.com/compute/v1/projects/{self.p}/global"
        return self.memo("proxies", lambda: self.c.list(f"{base}/targetHttpsProxies", "items")
                         + self.c.list(f"{base}/targetSslProxies", "items"))

    def ssl_policies(self) -> List[dict]:
        return self.memo("sslpol", lambda: self.c.list(
            f"https://compute.googleapis.com/compute/v1/projects/{self.p}/global/sslPolicies", "items"))

    def disks(self) -> List[dict]:
        return self.memo("disks", lambda: self.c.agg_list(
            f"https://compute.googleapis.com/compute/v1/projects/{self.p}/aggregated/disks", "disks"))

    def bq_tables(self, limit: int = 200):
        """(tables, truncated). Fetches each table individually, so it is capped."""
        def load():
            out, truncated = [], False
            for d in self.bq_datasets():
                did = d["datasetReference"]["datasetId"]
                refs = self.c.list(f"https://bigquery.googleapis.com/bigquery/v2/projects/{self.p}"
                                   f"/datasets/{did}/tables", "tables")
                for t in refs:
                    if len(out) >= limit:
                        truncated = True
                        break
                    tid = t["tableReference"]["tableId"]
                    full = self.c.get(f"https://bigquery.googleapis.com/bigquery/v2/projects/{self.p}"
                                      f"/datasets/{did}/tables/{tid}")
                    full["_label"] = f"{did}.{tid}"
                    out.append(full)
            return out, truncated
        return self.memo("bqtables", load)

    def service_accounts(self) -> List[dict]:
        return self.memo("sas", lambda: self.c.list(
            f"https://iam.googleapis.com/v1/projects/{self.p}/serviceAccounts", "accounts"))

    def sa_keys(self) -> Dict[str, List[dict]]:
        def load():
            out = {}
            for sa in self.service_accounts():
                data = self.c.get(f"https://iam.googleapis.com/v1/{sa['name']}/keys",
                                  {"keyTypes": "USER_MANAGED"})
                out[sa["email"]] = data.get("keys", []) or []
            return out
        return self.memo("sakeys", load)

    # Compute
    def instances(self) -> List[dict]:
        return self.memo("vms", lambda: self.c.agg_list(
            f"https://compute.googleapis.com/compute/v1/projects/{self.p}/aggregated/instances",
            "instances"))

    def project_metadata(self) -> Dict[str, str]:
        def load():
            data = self.c.get(f"https://compute.googleapis.com/compute/v1/projects/{self.p}")
            return meta_dict(data.get("commonInstanceMetadata"))
        return self.memo("pmeta", load)

    def firewalls(self) -> List[dict]:
        return self.memo("fw", lambda: self.c.list(
            f"https://compute.googleapis.com/compute/v1/projects/{self.p}/global/firewalls", "items"))

    def networks(self) -> List[dict]:
        return self.memo("nets", lambda: self.c.list(
            f"https://compute.googleapis.com/compute/v1/projects/{self.p}/global/networks", "items"))

    def subnets(self) -> List[dict]:
        return self.memo("subnets", lambda: self.c.agg_list(
            f"https://compute.googleapis.com/compute/v1/projects/{self.p}/aggregated/subnetworks",
            "subnetworks"))

    # DNS
    def dns_zones(self) -> List[dict]:
        return self.memo("dns", lambda: self.c.list(
            f"https://dns.googleapis.com/dns/v1/projects/{self.p}/managedZones", "managedZones"))

    # Logging / Monitoring
    def sinks(self) -> List[dict]:
        return self.memo("sinks", lambda: self.c.list(
            f"https://logging.googleapis.com/v2/projects/{self.p}/sinks", "sinks"))

    def log_metrics(self) -> List[dict]:
        return self.memo("metrics", lambda: self.c.list(
            f"https://logging.googleapis.com/v2/projects/{self.p}/metrics", "metrics"))

    def alert_policies(self) -> List[dict]:
        return self.memo("alerts", lambda: self.c.list(
            f"https://monitoring.googleapis.com/v3/projects/{self.p}/alertPolicies", "alertPolicies"))

    # Storage / SQL / BigQuery
    def buckets(self) -> List[dict]:
        return self.memo("buckets", lambda: self.c.list(
            "https://storage.googleapis.com/storage/v1/b", "items", {"project": self.p}))

    def sql_instances(self) -> List[dict]:
        return self.memo("sql", lambda: self.c.list(
            f"https://sqladmin.googleapis.com/v1/projects/{self.p}/instances", "items"))

    def bq_datasets(self) -> List[dict]:
        def load():
            refs = self.c.list(
                f"https://bigquery.googleapis.com/bigquery/v2/projects/{self.p}/datasets", "datasets")
            return [self.c.get(f"https://bigquery.googleapis.com/bigquery/v2/projects/{self.p}"
                               f"/datasets/{d['datasetReference']['datasetId']}") for d in refs]
        return self.memo("bq", load)


class OrgContext(Context):
    """Same interface as Context but scoped to an organization.

    Lets IAM / audit-logging check functions run unchanged at org level.
    ``.p`` is the label shown in results ("org:<id>").
    """

    def __init__(self, client, org_id: str):
        super().__init__(client, f"org:{org_id}")
        self.org_id = org_id

    def iam_policy(self) -> dict:
        return self.memo("iam", lambda: self.c.post(
            f"https://cloudresourcemanager.googleapis.com/v3/organizations/{self.org_id}:getIamPolicy",
            {"options": {"requestedPolicyVersion": 3}}))

    def inherited_policies(self):
        return [], []

    def inherited_sinks(self):
        return [], []

    def sinks(self) -> List[dict]:
        return self.memo("sinks", lambda: self.c.list(
            f"https://logging.googleapis.com/v2/organizations/{self.org_id}/sinks", "sinks"))

    def essential_contacts(self) -> List[dict]:
        return self.memo("contacts", lambda: self.c.list(
            f"https://essentialcontacts.googleapis.com/v1/organizations/{self.org_id}/contacts", "contacts"))

    def org_policy(self, constraint: str) -> dict:
        def load():
            try:
                return self.c.get(f"https://orgpolicy.googleapis.com/v2/organizations/{self.org_id}"
                                  f"/policies/{constraint}:getEffectivePolicy")
            except ApiError as exc:
                if exc.status == 404:
                    return {}
                raise
        return self.memo("op:" + constraint, load)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def meta_dict(meta) -> Dict[str, str]:
    return {i.get("key"): str(i.get("value", "")) for i in (meta or {}).get("items", []) or []}


def truthy(v) -> bool:
    return str(v).strip().lower() in ("true", "1", "yes")


def is_gke(inst: dict) -> bool:
    return inst.get("name", "").startswith("gke-") or "goog-gke-node" in (inst.get("labels") or {})


def short(url: str) -> str:
    return url.rsplit("/", 1)[-1] if url else ""


def inst_name(i: dict) -> str:
    return f"{i.get('name')} ({short(i.get('zone', ''))})"


def parse_time(s: str) -> datetime:
    s = re.sub(r"\.\d+", "", s).replace("Z", "+00:00")
    return datetime.fromisoformat(s)


def age_days(s: str) -> int:
    return (datetime.now(timezone.utc) - parse_time(s)).days


def public_members(bindings) -> List[str]:
    return sorted({m for b in bindings or [] for m in b.get("members", [])
                   if m in ("allUsers", "allAuthenticatedUsers")})


# --------------------------------------------------------------------------- #
# 1 - IAM
# --------------------------------------------------------------------------- #
@check("1.1", "Corporate login credentials are used (no personal @gmail.com accounts)", SEC_IAM, 1, "Medium",
       "Personal Gmail accounts are not centrally managed, lack enforced policies and may persist after "
       "an employee leaves.",
       "Replace user:*@gmail.com IAM members with managed corporate identities, then remove the bindings.")
def c_1_1(ctx):
    bad = sorted({m for b in ctx.iam_policy().get("bindings", []) for m in b.get("members", [])
                  if m.startswith("user:") and m.lower().endswith("@gmail.com")})
    return failed("Personal Gmail accounts hold roles", bad) if bad else passed(
        "No @gmail.com members in the IAM policy")


manual("1.2", "MFA / 2-Step Verification is enforced for all non-service accounts", SEC_IAM, 1, "High",
       "Verify in Cloud Identity / Google Workspace admin console that 2SV is enforced for every user.",
       "Admin console > Security > Authentication > 2-step verification: enforce for all org units.")
manual("1.3", "Security Key enforcement for admin accounts", SEC_IAM, 2, "Medium",
       "Privileged users should be required to use hardware security keys.",
       "Admin console > Security > 2-step verification: allow only security keys for privileged OUs.")


@check("1.4", "Service accounts have no user-managed keys", SEC_IAM, 1, "High",
       "User-managed service account keys are long-lived credentials that can leak.",
       "Delete user-managed keys (gcloud iam service-accounts keys delete) and use workload identity or "
       "short-lived credentials.")
def c_1_4(ctx):
    keys = ctx.sa_keys()
    bad = [f"{email}: {len(k)} key(s)" for email, k in keys.items() if k]
    return evaluate(len(keys), bad, "service accounts")


def _admin_role(role: str) -> bool:
    r = role.lower()
    return r in ("roles/owner", "roles/editor") or "admin" in r.rsplit("/", 1)[-1]


@check("1.5", "Service accounts do not have admin privileges", SEC_IAM, 1, "High",
       "Service accounts holding Owner/Editor/*Admin roles can lead to full project compromise.",
       "Remove admin roles from service accounts and grant least-privilege predefined/custom roles.")
def c_1_5(ctx):
    bad = [f"{m} -> {b['role']}" for b in ctx.iam_policy().get("bindings", []) if _admin_role(b["role"])
           for m in b.get("members", []) if m.startswith("serviceAccount:")]
    return failed("Service accounts with admin roles", bad) if bad else passed(
        "No service account has an admin role at project level")


@check("1.6", "No principals hold Service Account User / Token Creator at project level", SEC_IAM, 1, "High",
       "Project-level iam.serviceAccountUser or serviceAccountTokenCreator lets a principal impersonate "
       "every service account in the project.",
       "Grant these roles on individual service accounts instead of at project level.")
def c_1_6(ctx):
    roles = ("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator")
    bad = [f"{m} -> {b['role']}" for b in ctx.iam_policy().get("bindings", []) if b["role"] in roles
           for m in b.get("members", [])]
    return failed("Broad impersonation roles granted", bad) if bad else passed(
        "Neither role is granted at this level")


@check("1.7", "User-managed service account keys are rotated within 90 days", SEC_IAM, 1, "Medium",
       "Old keys increase the window in which a leaked key is useful.",
       "Create a new key, switch workloads to it, then delete the old key. Better: remove keys (1.4).")
def c_1_7(ctx):
    keys = ctx.sa_keys()
    total, bad = 0, []
    for email, ks in keys.items():
        for k in ks:
            total += 1
            if age_days(k["validAfterTime"]) > 90:
                bad.append(f"{email}: key {short(k['name'])[:12]}... is {age_days(k['validAfterTime'])} days old")
    return evaluate(total, bad, "user-managed keys")




def _kms_keys(ctx):
    def load():
        keys = []
        for loc in ctx.c.list(f"https://cloudkms.googleapis.com/v1/projects/{ctx.p}/locations", "locations"):
            lid = loc["locationId"]
            for ring in ctx.c.list(
                    f"https://cloudkms.googleapis.com/v1/projects/{ctx.p}/locations/{lid}/keyRings", "keyRings"):
                keys.extend(ctx.c.list(f"https://cloudkms.googleapis.com/v1/{ring['name']}/cryptoKeys",
                                       "cryptoKeys"))
        return keys
    return ctx.memo("kms", load)


@check("1.9", "Cloud KMS keys are not anonymously or publicly accessible", SEC_IAM, 1, "High",
       "allUsers / allAuthenticatedUsers on a CryptoKey exposes key usage to the internet.",
       "Remove allUsers and allAuthenticatedUsers from the key's IAM policy.")
def c_1_9(ctx):
    keys = _kms_keys(ctx)
    bad = []
    for k in keys:
        pol = ctx.c.get(f"https://cloudkms.googleapis.com/v1/{k['name']}:getIamPolicy")
        pm = public_members(pol.get("bindings"))
        if pm:
            bad.append(f"{k['name']}: {', '.join(pm)}")
    return evaluate(len(keys), bad, "KMS keys")


@check("1.10", "KMS encryption keys are rotated within 90 days", SEC_IAM, 1, "Medium",
       "Regular rotation limits the data exposed by one compromised key version.",
       "Set rotation period <= 90 days: gcloud kms keys update KEY --keyring R --location L "
       "--rotation-period 90d --next-rotation-time ...")
def c_1_10(ctx):
    keys = [k for k in _kms_keys(ctx) if k.get("purpose") == "ENCRYPT_DECRYPT"]
    bad = []
    for k in keys:
        period = k.get("rotationPeriod")
        if not period:
            bad.append(f"{k['name']}: no rotation period")
        elif int(period.rstrip("s")) > 90 * 86400:
            bad.append(f"{k['name']}: rotation period {int(period.rstrip('s')) // 86400} days")
    return evaluate(len(keys), bad, "symmetric KMS keys")


# --------------------------------------------------------------------------- #
# 2 - Logging & Monitoring
# --------------------------------------------------------------------------- #
@check("2.1", "Cloud Audit Logging is configured for all services and users", SEC_LOG, 1, "High",
       "ADMIN_READ, DATA_READ and DATA_WRITE must be enabled on allServices with no exempted members.",
       "IAM & Admin > Audit Logs: enable all three log types for 'Default Audit Config' / allServices and "
       "remove exemptions.")
def c_2_1(ctx):
    # Audit configs are additive down the hierarchy: evaluate org + folders + project together.
    inherited, notes = ctx.inherited_policies()
    cfgs = [("direct", c) for c in ctx.iam_policy().get("auditConfigs", []) or []]
    for label, pol in inherited:
        cfgs += [(label, c) for c in pol.get("auditConfigs", []) or []]
    need = {"ADMIN_READ", "DATA_READ", "DATA_WRITE"}
    enabled = {lc["logType"] for _, c in cfgs if c.get("service") == "allServices"
               for lc in c.get("auditLogConfigs", [])}
    problems = []
    if need - enabled:
        problems.append("allServices missing: " + ", ".join(sorted(need - enabled)))
    for label, c in cfgs:
        for lc in c.get("auditLogConfigs", []):
            if lc.get("exemptedMembers"):
                problems.append(f"Exempted members ({label}, {c.get('service')}, {lc['logType']}): "
                                + ", ".join(lc["exemptedMembers"]))
    problems += [f"Not evaluated: {n}" for n in notes] if problems else []
    if problems:
        return failed("Audit logging incomplete", problems)
    suffix = f" (inherited config considered from {len(inherited)} ancestor(s))" if inherited else ""
    return passed("All log types enabled on allServices with no exemptions" + suffix
                  + ("; " + "; ".join(notes) if notes else ""))


@check("2.2", "A log sink exports all log entries", SEC_LOG, 1, "Medium",
       "Exporting all logs to a sink preserves them beyond default bucket retention for forensics.",
       "Create a sink with an empty filter and no exclusions to Cloud Storage, BigQuery or Pub/Sub.")
def c_2_2(ctx):
    sinks = ctx.sinks()
    def catch_all(s):
        return not s.get("filter") and not s.get("exclusions") and not s.get("disabled")
    good = [s["name"] for s in sinks if catch_all(s)]
    inherited, notes = ctx.inherited_sinks()
    good += [f"{label}/{s['name']} (aggregated)" for label, s in inherited if catch_all(s)]
    if good:
        return passed("Catch-all sink(s): " + ", ".join(good))
    return failed("No enabled catch-all sink at project, folder or organization level",
                  [s["name"] for s in sinks] + [f"Not evaluated: {n}" for n in notes])


@check("2.3", "Retention policies on log-sink storage buckets are locked", SEC_LOG, 2, "Medium",
       "Bucket Lock prevents log tampering or early deletion.",
       "gsutil retention set <period> gs://BUCKET; gsutil retention lock gs://BUCKET")
def c_2_3(ctx):
    prefix = "storage.googleapis.com/"
    dests = [s for s in ctx.sinks() if s.get("destination", "").startswith(prefix)]
    bad = []
    for s in dests:
        bname = s["destination"][len(prefix):]
        rp = ctx.c.get(f"https://storage.googleapis.com/storage/v1/b/{bname}").get("retentionPolicy")
        if not rp or not rp.get("isLocked"):
            bad.append(f"{bname}: " + ("retention policy not locked" if rp else "no retention policy"))
    return evaluate(len(dests), bad, "Cloud Storage log sinks")


_METRIC_CHECKS = [
    ("2.4", "Log metric filter and alert exist for project ownership changes",
     ["projectownerinvitee", "roles/owner", "setiampolicy"]),
    ("2.5", "Log metric filter and alert exist for Audit Configuration changes",
     ["setiampolicy", "auditconfigdeltas"]),
    ("2.6", "Log metric filter and alert exist for Custom Role changes",
     ['resource.type="iam_role"', "createrole", "deleterole", "updaterole"]),
    ("2.7", "Log metric filter and alert exist for VPC Network Firewall changes",
     ["gce_firewall_rule", "compute.firewalls.insert", "compute.firewalls.patch", "compute.firewalls.delete"]),
    ("2.8", "Log metric filter and alert exist for VPC Route changes",
     ["gce_route", "compute.routes.insert", "compute.routes.delete"]),
    ("2.9", "Log metric filter and alert exist for VPC Network changes",
     ["gce_network", "compute.networks.insert", "compute.networks.patch", "compute.networks.delete"]),
    ("2.10", "Log metric filter and alert exist for Cloud Storage IAM permission changes",
     ["gcs_bucket", "storage.setiampermissions"]),
    ("2.11", "Log metric filter and alert exist for SQL instance configuration changes",
     ["cloudsql_database", "cloudsql.instances.update"]),
]


def _make_metric_check(cid, title, keywords):
    @check(cid, title, SEC_LOG, 1, "Medium",
           "A log-based metric whose filter matches these events, with an enabled alerting policy "
           f"on it, is required. Filter must reference: {', '.join(keywords)}.",
           "Logging > Log-based Metrics: create a metric with the CIS-recommended filter, then create "
           "an alerting policy on logging.googleapis.com/user/<metric> with a notification channel.")
    def fn(ctx):
        metrics = []
        for m in ctx.log_metrics():
            flt = (m.get("filter") or "").lower().replace(" ", "")
            if all(k.replace(" ", "") in flt for k in keywords):
                metrics.append(m["name"])
        if not metrics:
            return failed("No log-based metric with a matching filter", [])
        try:
            alerts = ctx.alert_policies()
        except ApiError as exc:
            if exc.service_disabled:
                return failed("Metric exists but Cloud Monitoring API is not enabled - no alerting", metrics)
            raise
        for a in alerts:
            if not a.get("enabled", True):
                continue
            for cond in a.get("conditions", []):
                blob = str(cond)
                if any(f"logging.googleapis.com/user/{m}" in blob for m in metrics):
                    return passed(f"Metric '{', '.join(metrics)}' alerted by policy '{a.get('displayName')}'")
        return failed("Metric exists but no enabled alerting policy uses it", metrics)
    return fn


for _cid, _title, _kw in _METRIC_CHECKS:
    _make_metric_check(_cid, _title, _kw)


@check("2.13", "Cloud Asset Inventory is enabled", SEC_LOG, 1, "Low",
       "Asset inventory provides a history of resources and IAM policies for audit and incident response.",
       "gcloud services enable cloudasset.googleapis.com")
def c_2_13(ctx):
    s = ctx.c.get(f"https://serviceusage.googleapis.com/v1/projects/{ctx.p}/services/cloudasset.googleapis.com")
    return passed("cloudasset.googleapis.com is ENABLED") if s.get("state") == "ENABLED" else failed(
        "Cloud Asset API is not enabled", ["cloudasset.googleapis.com"])


# --------------------------------------------------------------------------- #
# 3 - Networking
# --------------------------------------------------------------------------- #
@check("3.1", "The default network does not exist", SEC_NET, 2, "Medium",
       "The default network ships with permissive pre-populated firewall rules.",
       "Create custom VPC networks and delete the 'default' network.")
def c_3_1(ctx):
    nets = ctx.networks()
    return failed("Default network exists", ["default"]) if any(n["name"] == "default" for n in nets) \
        else passed("No default network")


@check("3.2", "Legacy networks do not exist", SEC_NET, 1, "Medium",
       "Legacy networks cannot use subnets and lack modern controls.",
       "Migrate to a VPC subnet-mode network and delete the legacy network.")
def c_3_2(ctx):
    bad = [n["name"] for n in ctx.networks() if n.get("IPv4Range")]
    return failed("Legacy networks present", bad) if bad else passed("No legacy networks")


@check("3.3", "DNSSEC is enabled for Cloud DNS public zones", SEC_NET, 1, "Medium",
       "DNSSEC protects against DNS spoofing and cache poisoning.",
       "gcloud dns managed-zones update ZONE --dnssec-state on")
def c_3_3(ctx):
    zones = [z for z in ctx.dns_zones() if z.get("visibility", "public") == "public"]
    bad = [z["name"] for z in zones if (z.get("dnssecConfig") or {}).get("state") != "on"]
    return evaluate(len(zones), bad, "public DNS zones")


def _dns_algo(zone_type, ctx):
    zones = [z for z in ctx.dns_zones() if z.get("visibility", "public") == "public"
             and (z.get("dnssecConfig") or {}).get("state") == "on"]
    bad = []
    for z in zones:
        for spec in (z["dnssecConfig"].get("defaultKeySpecs") or []):
            if spec.get("keyType") == zone_type and str(spec.get("algorithm", "")).lower() == "rsasha1":
                bad.append(z["name"])
    return evaluate(len(zones), bad, "DNSSEC-enabled zones")


@check("3.4", "RSASHA1 is not used for the DNSSEC key-signing key", SEC_NET, 1, "Medium",
       "RSASHA1 is a weak, deprecated algorithm.",
       "Re-create the zone's KSK with RSASHA256 or ECDSA (gcloud dns managed-zones update ... "
       "--ksk-algorithm rsasha256).")
def c_3_4(ctx):
    return _dns_algo("keySigning", ctx)


@check("3.5", "RSASHA1 is not used for the DNSSEC zone-signing key", SEC_NET, 1, "Medium",
       "RSASHA1 is a weak, deprecated algorithm.",
       "gcloud dns managed-zones update ZONE --zsk-algorithm rsasha256")
def c_3_5(ctx):
    return _dns_algo("zoneSigning", ctx)


def _port_open(allowed: List[dict], port: int) -> bool:
    for a in allowed or []:
        if a.get("IPProtocol") not in ("tcp", "all"):
            continue
        ports = a.get("ports")
        if not ports or a.get("IPProtocol") == "all":
            return True
        for p in ports:
            lo, _, hi = p.partition("-")
            if int(lo) <= port <= int(hi or lo):
                return True
    return False


def _exposed_fw(ctx, port):
    bad = []
    for f in ctx.firewalls():
        if f.get("direction", "INGRESS") != "INGRESS" or f.get("disabled"):
            continue
        if not {"0.0.0.0/0", "::/0"} & set(f.get("sourceRanges", [])):
            continue
        if _port_open(f.get("allowed"), port):
            bad.append(f["name"])
    return bad


@check("3.6", "SSH (22) is not open to the internet", SEC_NET, 1, "High",
       "Firewall rules allowing 0.0.0.0/0 to port 22 expose instances to brute force.",
       "Restrict source ranges to trusted CIDRs or use IAP TCP forwarding (35.235.240.0/20).")
def c_3_6(ctx):
    bad = _exposed_fw(ctx, 22)
    return failed("Ingress rules allow SSH from anywhere", bad) if bad else passed("No rule exposes port 22")


@check("3.7", "RDP (3389) is not open to the internet", SEC_NET, 1, "High",
       "Firewall rules allowing 0.0.0.0/0 to port 3389 expose Windows hosts to attack.",
       "Restrict source ranges or use IAP / a bastion host.")
def c_3_7(ctx):
    bad = _exposed_fw(ctx, 3389)
    return failed("Ingress rules allow RDP from anywhere", bad) if bad else passed("No rule exposes port 3389")


@check("3.8", "VPC Flow Logs are enabled for every subnet", SEC_NET, 1, "Medium",
       "Flow logs provide visibility for network forensics and anomaly detection.",
       "gcloud compute networks subnets update SUBNET --region R --enable-flow-logs")
def c_3_8(ctx):
    subs = [s for s in ctx.subnets() if s.get("purpose", "PRIVATE") == "PRIVATE"]
    bad = [f"{s['name']} ({short(s.get('region', ''))})" for s in subs
           if not (s.get("logConfig", {}).get("enable") or s.get("enableFlowLogs"))]
    return evaluate(len(subs), bad, "subnets")


# --------------------------------------------------------------------------- #
# 4 - Virtual Machines
# --------------------------------------------------------------------------- #
def _vms(ctx, skip_gke=True):
    return [i for i in ctx.instances() if not (skip_gke and is_gke(i))]


@check("4.1", "Instances do not use the default service account", SEC_VM, 1, "High",
       "The default compute SA has the broad Editor role.",
       "Create a dedicated least-privilege service account and attach it (instance must be stopped).")
def c_4_1(ctx):
    vms = _vms(ctx)
    bad = [inst_name(i) for i in vms for sa in i.get("serviceAccounts", [])
           if sa.get("email", "").endswith("-compute@developer.gserviceaccount.com")]
    return evaluate(len(vms), bad, "VM instances")


@check("4.2", "Instances are not given full API access with the default service account", SEC_VM, 1, "High",
       "The cloud-platform scope combined with the default SA grants near-total access.",
       "Use a custom SA with only the required scopes / IAM roles.")
def c_4_2(ctx):
    vms = _vms(ctx)
    bad = [inst_name(i) for i in vms for sa in i.get("serviceAccounts", [])
           if sa.get("email", "").endswith("-compute@developer.gserviceaccount.com")
           and "https://www.googleapis.com/auth/cloud-platform" in sa.get("scopes", [])]
    return evaluate(len(vms), bad, "VM instances")


@check("4.3", "'Block Project-wide SSH keys' is enabled for instances", SEC_VM, 1, "Medium",
       "Project-wide SSH keys grant access to every instance that does not block them.",
       "gcloud compute instances add-metadata VM --metadata block-project-ssh-keys=TRUE")
def c_4_3(ctx):
    vms = _vms(ctx)
    bad = [inst_name(i) for i in vms if not truthy(meta_dict(i.get("metadata")).get("block-project-ssh-keys"))]
    return evaluate(len(vms), bad, "VM instances")


@check("4.4", "OS Login is enabled for the project", SEC_VM, 1, "Medium",
       "OS Login ties SSH access to IAM identities and supports 2SV and central revocation.",
       "gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE")
def c_4_4(ctx):
    if not ctx.instances():
        return not_applicable("No VM instances in this project")
    return passed("enable-oslogin=TRUE in project metadata") if truthy(
        ctx.project_metadata().get("enable-oslogin")) else failed(
        "enable-oslogin is not TRUE in project metadata", ["project metadata"])


@check("4.5", "Interactive serial port access is disabled on instances", SEC_VM, 1, "Medium",
       "The serial console bypasses network controls and is exposed to brute force.",
       "gcloud compute instances add-metadata VM --metadata serial-port-enable=FALSE")
def c_4_5(ctx):
    vms = ctx.instances()
    project_on = truthy(ctx.project_metadata().get("serial-port-enable")) if vms else False
    bad = []
    for i in vms:
        v = meta_dict(i.get("metadata")).get("serial-port-enable")
        if truthy(v) or (v is None and project_on):
            bad.append(inst_name(i))
    return evaluate(len(vms), bad, "VM instances")


@check("4.6", "IP forwarding is disabled on instances", SEC_VM, 1, "Medium",
       "IP forwarding allows an instance to route traffic not addressed to it (data exfiltration risk).",
       "Re-create the instance without --can-ip-forward.")
def c_4_6(ctx):
    vms = _vms(ctx)
    bad = [inst_name(i) for i in vms if i.get("canIpForward")]
    return evaluate(len(vms), bad, "VM instances")




@check("4.8", "Compute instances have Shielded VM vTPM and integrity monitoring enabled", SEC_VM, 2, "Medium",
       "Shielded VM protects against boot-level malware and rootkits.",
       "gcloud compute instances update VM --shielded-vtpm --shielded-integrity-monitoring")
def c_4_8(ctx):
    vms = _vms(ctx)
    bad = [inst_name(i) for i in vms
           if not (i.get("shieldedInstanceConfig", {}).get("enableVtpm")
                   and i.get("shieldedInstanceConfig", {}).get("enableIntegrityMonitoring"))]
    return evaluate(len(vms), bad, "VM instances")


@check("4.9", "Instances do not have public IP addresses", SEC_VM, 2, "High",
       "Public IPs expose instances directly to the internet.",
       "Remove the external IP (delete-access-config) and use Cloud NAT / IAP / load balancers.")
def c_4_9(ctx):
    vms = _vms(ctx)
    bad = [inst_name(i) for i in vms if any(n.get("accessConfigs") for n in i.get("networkInterfaces", []))]
    return evaluate(len(vms), bad, "VM instances")


# --------------------------------------------------------------------------- #
# 5 - Storage
# --------------------------------------------------------------------------- #
@check("5.1", "Cloud Storage buckets are not anonymously or publicly accessible", SEC_STO, 1, "High",
       "allUsers / allAuthenticatedUsers bindings expose bucket data to the internet.",
       "gsutil iam ch -d allUsers gs://BUCKET ; gsutil iam ch -d allAuthenticatedUsers gs://BUCKET; "
       "enable Public Access Prevention.")
def c_5_1(ctx):
    buckets = ctx.buckets()
    bad = []
    for b in buckets:
        pol = ctx.c.get(f"https://storage.googleapis.com/storage/v1/b/{b['name']}/iam")
        pm = public_members(pol.get("bindings"))
        if pm:
            bad.append(f"{b['name']}: {', '.join(pm)}")
    return evaluate(len(buckets), bad, "buckets")


@check("5.2", "Uniform bucket-level access is enabled on buckets", SEC_STO, 2, "Medium",
       "Uniform access disables object ACLs so IAM is the single source of truth.",
       "gsutil uniformbucketlevelaccess set on gs://BUCKET")
def c_5_2(ctx):
    buckets = ctx.buckets()
    bad = [b["name"] for b in buckets
           if not b.get("iamConfiguration", {}).get("uniformBucketLevelAccess", {}).get("enabled")]
    return evaluate(len(buckets), bad, "buckets")


# --------------------------------------------------------------------------- #
# 6 - Cloud SQL
# --------------------------------------------------------------------------- #
def _sql(ctx):
    return ctx.sql_instances()


@check("6.4", "Cloud SQL requires SSL for all incoming connections", SEC_SQL, 1, "High",
       "Unencrypted connections can be intercepted.",
       "gcloud sql instances patch INSTANCE --ssl-mode=ENCRYPTED_ONLY")
def c_6_4(ctx):
    inst = _sql(ctx)
    bad = []
    for i in inst:
        ipc = i.get("settings", {}).get("ipConfiguration", {})
        if not (ipc.get("requireSsl") or ipc.get("sslMode") in
                ("ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED")):
            bad.append(i["name"])
    return evaluate(len(inst), bad, "Cloud SQL instances")


@check("6.5", "Cloud SQL authorized networks do not include 0.0.0.0/0", SEC_SQL, 1, "High",
       "0.0.0.0/0 allows connection attempts from any address.",
       "Restrict authorized networks to specific CIDRs or use the Cloud SQL Auth Proxy / private IP.")
def c_6_5(ctx):
    inst = _sql(ctx)
    bad = [i["name"] for i in inst
           if any(n.get("value") in ("0.0.0.0/0", "::/0")
                  for n in i.get("settings", {}).get("ipConfiguration", {}).get("authorizedNetworks", []))]
    return evaluate(len(inst), bad, "Cloud SQL instances")


@check("6.6", "Cloud SQL instances do not have public IPs", SEC_SQL, 2, "High",
       "Public IPv4 addresses expose databases to the internet.",
       "gcloud sql instances patch INSTANCE --no-assign-ip --network=VPC")
def c_6_6(ctx):
    inst = _sql(ctx)
    bad = [i["name"] for i in inst if i.get("settings", {}).get("ipConfiguration", {}).get("ipv4Enabled")]
    return evaluate(len(inst), bad, "Cloud SQL instances")


@check("6.7", "Cloud SQL automated backups are enabled", SEC_SQL, 1, "Medium",
       "Backups allow recovery from data loss or corruption.",
       "gcloud sql instances patch INSTANCE --backup-start-time=HH:MM")
def c_6_7(ctx):
    inst = [i for i in _sql(ctx) if i.get("instanceType") != "READ_REPLICA_INSTANCE"]
    bad = [i["name"] for i in inst if not i.get("settings", {}).get("backupConfiguration", {}).get("enabled")]
    return evaluate(len(inst), bad, "Cloud SQL instances")


# --------------------------------------------------------------------------- #
# 7 - BigQuery
# --------------------------------------------------------------------------- #
@check("7.1", "BigQuery datasets are not anonymously or publicly accessible", SEC_BQ, 1, "High",
       "Public datasets expose data to any (authenticated) Google user.",
       "Remove allUsers / allAuthenticatedUsers from the dataset's access list.")
def c_7_1(ctx):
    ds = ctx.bq_datasets()
    bad = []
    for d in ds:
        for a in d.get("access", []) or []:
            if a.get("specialGroup") == "allAuthenticatedUsers" or \
                    a.get("iamMember") in ("allUsers", "allAuthenticatedUsers"):
                bad.append(d["datasetReference"]["datasetId"])
                break
    return evaluate(len(ds), bad, "datasets")


@check("7.3", "BigQuery datasets use a customer-managed default encryption key", SEC_BQ, 2, "Medium",
       "CMEK gives control over key lifecycle for data at rest.",
       "bq update --default_kms_key KEY PROJECT:DATASET")
def c_7_3(ctx):
    ds = ctx.bq_datasets()
    bad = [d["datasetReference"]["datasetId"] for d in ds
           if not (d.get("defaultEncryptionConfiguration") or {}).get("kmsKeyName")]
    return evaluate(len(ds), bad, "datasets")


# Register the extended checks (API keys, SQL flags, GKE, Dataproc, org policy).
from . import checks_extra  # noqa: E402,F401
