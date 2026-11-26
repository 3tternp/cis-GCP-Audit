"""Extended coverage: API keys, Cloud SQL flags, GKE, Dataproc and Organization Policy checks.

Imported at the bottom of ``checks.py`` so every check registers in the same REGISTRY.
"""
from __future__ import annotations

from .checks import (SEC_DP, SEC_GKE, SEC_IAM, SEC_OP, SEC_SQL, age_days, check, short)
from .models import evaluate, failed, passed


# --------------------------------------------------------------------------- #
# 1.12-1.15 - API keys
# --------------------------------------------------------------------------- #
def _key_label(k: dict) -> str:
    return k.get("displayName") or short(k.get("name", ""))


@check("1.12", "API keys are not created for the project", SEC_IAM, 2, "Medium",
       "API keys are bearer secrets with weak identity binding; prefer service accounts / OAuth.",
       "Delete API keys: gcloud services api-keys delete KEY_ID")
def c_1_12(ctx):
    keys = ctx.api_keys()
    return failed(f"{len(keys)} API key(s) exist", [_key_label(k) for k in keys]) if keys else passed(
        "No API keys in this project")


@check("1.13", "API keys are restricted to specific applications (browser/server/app)", SEC_IAM, 2, "Medium",
       "An unrestricted key can be used from anywhere if leaked.",
       "Set HTTP referrer, IP, Android or iOS application restrictions on each key.")
def c_1_13(ctx):
    keys = ctx.api_keys()
    kinds = ("browserKeyRestrictions", "serverKeyRestrictions", "androidKeyRestrictions", "iosKeyRestrictions")
    bad = [_key_label(k) for k in keys if not any((k.get("restrictions") or {}).get(x) for x in kinds)]
    return evaluate(len(keys), bad, "API keys")


@check("1.14", "API keys are restricted to only the APIs the application needs", SEC_IAM, 2, "Medium",
       "Restricting API targets limits what a leaked key can be used for.",
       "Set API restrictions on each key (gcloud services api-keys update KEY --api-target=service=...).")
def c_1_14(ctx):
    keys = ctx.api_keys()
    bad = []
    for k in keys:
        targets = (k.get("restrictions") or {}).get("apiTargets") or []
        if not targets or any(t.get("service") == "cloudapis.googleapis.com" for t in targets):
            bad.append(_key_label(k))
    return evaluate(len(keys), bad, "API keys")


@check("1.15", "API keys are rotated within 90 days", SEC_IAM, 2, "Medium",
       "Old keys have a longer exposure window.",
       "Create a replacement key with the same restrictions, migrate clients, delete the old key.")
def c_1_15(ctx):
    keys = ctx.api_keys()
    bad = [f"{_key_label(k)}: {age_days(k['createTime'])} days old" for k in keys
           if age_days(k["createTime"]) > 90]
    return evaluate(len(keys), bad, "API keys")


# --------------------------------------------------------------------------- #
# 6.1-6.3 - Cloud SQL database flags
# --------------------------------------------------------------------------- #
# (id, engine prefix, flag, compliant(value), value when flag is unset, title)
_SQL_FLAGS = [
    ("6.1.2", "MYSQL", "skip_show_database", lambda v: v == "on", "off",
     "MySQL: 'skip_show_database' flag is 'on'"),
    ("6.1.3", "MYSQL", "local_infile", lambda v: v == "off", "on",
     "MySQL: 'local_infile' flag is 'off'"),
    ("6.2.1", "POSTGRES", "log_error_verbosity", lambda v: v in ("default", "verbose"), "default",
     "PostgreSQL: 'log_error_verbosity' is 'default' or stricter (not 'terse')"),
    ("6.2.2", "POSTGRES", "log_connections", lambda v: v == "on", "off",
     "PostgreSQL: 'log_connections' flag is 'on'"),
    ("6.2.3", "POSTGRES", "log_disconnections", lambda v: v == "on", "off",
     "PostgreSQL: 'log_disconnections' flag is 'on'"),
    ("6.2.7", "POSTGRES", "log_min_duration_statement", lambda v: v == "-1", "-1",
     "PostgreSQL: 'log_min_duration_statement' is '-1' (statement text not logged)"),
    ("6.2.8", "POSTGRES", "cloudsql.enable_pgaudit", lambda v: v == "on", "off",
     "PostgreSQL: 'cloudsql.enable_pgaudit' flag is 'on'"),
    ("6.3.1", "SQLSERVER", "external scripts enabled", lambda v: v == "off", "off",
     "SQL Server: 'external scripts enabled' is 'off'"),
    ("6.3.2", "SQLSERVER", "cross db ownership chaining", lambda v: v == "off", "off",
     "SQL Server: 'cross db ownership chaining' is 'off'"),
    ("6.3.3", "SQLSERVER", "user connections", lambda v: v == "0", "0",
     "SQL Server: 'user connections' is '0' (not capped by flag)"),
    ("6.3.4", "SQLSERVER", "user options", lambda v: v == "", "",
     "SQL Server: 'user options' flag is not configured"),
    ("6.3.5", "SQLSERVER", "remote access", lambda v: v == "off", "on",
     "SQL Server: 'remote access' is 'off'"),
    ("6.3.6", "SQLSERVER", "3625", lambda v: v == "off", "off",
     "SQL Server: trace flag '3625' is 'off'"),
    ("6.3.7", "SQLSERVER", "contained database authentication", lambda v: v == "off", "off",
     "SQL Server: 'contained database authentication' is 'off'"),
]


def _make_sql_flag_check(cid, engine, flag, ok, default, title):
    @check(cid, title, SEC_SQL, 1, "Medium",
           f"Cloud SQL database flag '{flag}' must be configured securely. "
           f"If the flag is unset the engine default ('{default}') applies.",
           f"gcloud sql instances patch INSTANCE --database-flags={flag}=<value> "
           "(this command replaces ALL existing flags - include them in the same command).")
    def fn(ctx):
        inst = [i for i in ctx.sql_instances() if str(i.get("databaseVersion", "")).startswith(engine)]
        bad = []
        for i in inst:
            flags = {f.get("name"): str(f.get("value", "")).lower()
                     for f in i.get("settings", {}).get("databaseFlags", []) or []}
            val = flags.get(flag, default)
            if not ok(val):
                bad.append(f"{i['name']}: {flag}={val!r}" + ("" if flag in flags else " (engine default)"))
        return evaluate(len(inst), bad, f"{engine.title()} instances")
    return fn


for _spec in _SQL_FLAGS:
    _make_sql_flag_check(*_spec)


# --------------------------------------------------------------------------- #
# 8 - GKE
# --------------------------------------------------------------------------- #
def _cluster_label(c: dict) -> str:
    return f"{c.get('name')} ({c.get('location', c.get('zone', ''))})"


def _pools(c):
    return c.get("nodePools", []) or []


def _make_gke_check(cid, title, severity, desc, rem, compliant):
    @check(cid, title, SEC_GKE, 1 if severity == "High" else 2, severity, desc, rem)
    def fn(ctx):
        clusters = ctx.gke_clusters()
        return evaluate(len(clusters), [_cluster_label(c) for c in clusters if not compliant(c)],
                        "GKE clusters")
    return fn


_GKE_CHECKS = [
    ("8.1", "GKE clusters use private nodes", "High",
     "Nodes with public IPs are directly reachable from the internet.",
     "Re-create the cluster with --enable-private-nodes.",
     lambda c: (c.get("privateClusterConfig") or {}).get("enablePrivateNodes", False)),
    ("8.2", "GKE control plane has authorized networks enabled", "High",
     "Without authorized networks the API server is reachable from any IP.",
     "gcloud container clusters update C --enable-master-authorized-networks --master-authorized-networks=CIDR",
     lambda c: (c.get("masterAuthorizedNetworksConfig") or {}).get("enabled", False)),
    ("8.3", "GKE network policy (or Dataplane V2) is enabled", "Medium",
     "Network policies restrict pod-to-pod traffic.",
     "gcloud container clusters update C --enable-network-policy, or use --enable-dataplane-v2.",
     lambda c: (c.get("networkPolicy") or {}).get("enabled", False)
     or (c.get("networkConfig") or {}).get("datapathProvider") == "ADVANCED_DATAPATH"),
    ("8.4", "GKE legacy ABAC authorization is disabled", "High",
     "Legacy ABAC grants overly broad permissions to all service accounts.",
     "gcloud container clusters update C --no-enable-legacy-authorization",
     lambda c: not (c.get("legacyAbac") or {}).get("enabled", False)),
    ("8.5", "GKE Cloud Logging is enabled", "Medium",
     "Cluster and workload logs are required for detection and forensics.",
     "gcloud container clusters update C --logging=SYSTEM,WORKLOAD",
     lambda c: c.get("loggingService", "logging.googleapis.com/kubernetes") != "none"),
    ("8.6", "GKE Cloud Monitoring is enabled", "Medium",
     "Monitoring is required to detect anomalies.",
     "gcloud container clusters update C --monitoring=SYSTEM",
     lambda c: c.get("monitoringService", "monitoring.googleapis.com/kubernetes") != "none"),
    ("8.7", "GKE Workload Identity is enabled", "Medium",
     "Workload Identity avoids sharing node service-account credentials with every pod.",
     "gcloud container clusters update C --workload-pool=PROJECT.svc.id.goog",
     lambda c: bool((c.get("workloadIdentityConfig") or {}).get("workloadPool"))),
    ("8.8", "GKE Shielded GKE Nodes are enabled", "Medium",
     "Shielded nodes protect against node impersonation and rootkits.",
     "gcloud container clusters update C --enable-shielded-nodes",
     lambda c: (c.get("shieldedNodes") or {}).get("enabled", False)),
    ("8.9", "GKE node auto-upgrade is enabled on all node pools", "Medium",
     "Auto-upgrade keeps nodes patched.",
     "gcloud container node-pools update P --cluster C --enable-autoupgrade",
     lambda c: all((p.get("management") or {}).get("autoUpgrade", False) for p in _pools(c))),
    ("8.10", "GKE client certificate authentication is disabled", "High",
     "Client certificates cannot be revoked and bypass IAM.",
     "Re-create the cluster without --issue-client-certificate.",
     lambda c: not ((c.get("masterAuth") or {}).get("clientCertificateConfig") or {}).get(
         "issueClientCertificate", False)),
    ("8.11", "GKE nodes use Container-Optimized OS", "Medium",
     "COS has a minimal attack surface and automatic updates.",
     "Create node pools with --image-type=COS_CONTAINERD.",
     lambda c: all(str((p.get("config") or {}).get("imageType", "COS")).upper().startswith("COS")
                   for p in _pools(c))),
    ("8.12", "GKE nodes do not use the default Compute Engine service account", "High",
     "The default SA has the broad Editor role.",
     "Create node pools with a dedicated least-privilege --service-account.",
     lambda c: all((p.get("config") or {}).get("serviceAccount", "default") != "default"
                   and not str((p.get("config") or {}).get("serviceAccount", "")).endswith(
                       "-compute@developer.gserviceaccount.com") for p in _pools(c))),
    ("8.13", "GKE cluster is enrolled in a release channel", "Low",
     "Release channels provide managed, timely upgrades.",
     "gcloud container clusters update C --release-channel=regular",
     lambda c: (c.get("releaseChannel") or {}).get("channel") not in (None, "", "UNSPECIFIED")),
]
for _spec in _GKE_CHECKS:
    _make_gke_check(*_spec)


# --------------------------------------------------------------------------- #
# 9 - Dataproc
# --------------------------------------------------------------------------- #
@check("9.1", "Dataproc clusters use internal IPs only", SEC_DP, 2, "High",
       "Cluster VMs with public IPs are exposed to the internet.",
       "Create clusters with --no-address on a subnet with Private Google Access.")
def c_9_1(ctx):
    cl = ctx.dataproc_clusters()
    bad = [c["clusterName"] for c in cl
           if not (c.get("config", {}).get("gceClusterConfig") or {}).get("internalIpOnly", False)]
    return evaluate(len(cl), bad, "Dataproc clusters")


@check("9.2", "Dataproc cluster disks are encrypted with customer-managed keys", SEC_DP, 2, "Medium",
       "CMEK gives control over key lifecycle for data at rest.",
       "Create clusters with --gce-pd-kms-key.")
def c_9_2(ctx):
    cl = ctx.dataproc_clusters()
    bad = [c["clusterName"] for c in cl
           if not (c.get("config", {}).get("encryptionConfig") or {}).get("gcePdKmsKeyName")]
    return evaluate(len(cl), bad, "Dataproc clusters")


# --------------------------------------------------------------------------- #
# 10 - Organization Policy (preventive guardrails; not numbered by CIS)
# --------------------------------------------------------------------------- #
_ORG_POLICIES = [
    ("10.1", "compute.skipDefaultNetworkCreation", "Default network creation is skipped", "Medium"),
    ("10.2", "iam.disableServiceAccountKeyCreation", "Service account key creation is disabled", "High"),
    ("10.3", "compute.requireOsLogin", "OS Login is required on VMs", "Medium"),
    ("10.4", "compute.disableSerialPortAccess", "VM serial port access is disabled", "Medium"),
    ("10.5", "storage.uniformBucketLevelAccess", "Uniform bucket-level access is required", "Medium"),
    ("10.6", "storage.publicAccessPrevention", "Public access prevention is enforced on buckets", "High"),
    ("10.7", "sql.restrictPublicIp", "Cloud SQL public IPs are restricted", "High"),
    ("10.8", "sql.restrictAuthorizedNetworks", "Cloud SQL authorized networks are restricted", "Medium"),
    ("10.9", "compute.vmExternalIpAccess", "VM external IP access is denied (deny all)", "High"),
    ("10.10", "compute.requireShieldedVm", "Shielded VM is required", "Medium"),
    ("10.11", "iam.automaticIamGrantsForDefaultServiceAccounts",
     "Default service accounts are not automatically granted Editor", "Medium"),
]


def _make_org_policy_check(cid, constraint, title, severity):
    @check(cid, f"Org policy: {title}", SEC_OP, 2, severity,
           f"The effective organization policy 'constraints/{constraint}' should be enforced on this project "
           "so the related misconfiguration cannot be introduced.",
           f"Console > IAM & Admin > Organization Policies: enforce constraints/{constraint} "
           "at the organization or folder (gcloud org-policies set-policy).")
    def fn(ctx):
        pol = ctx.effective_org_policy(constraint)
        rules = (pol.get("spec") or {}).get("rules", []) or []
        enforced = any(r.get("enforce") is True or r.get("denyAll") is True for r in rules)
        return passed(f"constraints/{constraint} is enforced") if enforced else failed(
            f"constraints/{constraint} is not enforced", [constraint])
    return fn


for _spec in _ORG_POLICIES:
    _make_org_policy_check(*_spec)
