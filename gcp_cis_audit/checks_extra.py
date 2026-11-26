"""Extended coverage: API keys, Cloud SQL flags, GKE, Dataproc and Organization Policy checks.

Imported at the bottom of ``checks.py`` so every check registers in the same REGISTRY.
"""
from __future__ import annotations

from .checks import (SEC_BQ, SEC_DP, SEC_GKE, SEC_IAM, SEC_LOG, SEC_NET, SEC_OP, SEC_ORG, SEC_SQL, SEC_VM,
                     _vms, age_days, c_1_1, c_1_5, c_1_6, c_2_1, check, inst_name, short)
from .client import ApiError
from .models import evaluate, failed, not_applicable, passed


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
    ("10.12", "iam.allowedPolicyMemberDomains",
     "Domain-restricted sharing limits IAM members to allowed domains", "High", "list"),
]


def _make_org_policy_check(cid, constraint, title, severity, kind="bool"):
    @check(cid, f"Org policy: {title}", SEC_OP, 2, severity,
           f"The effective organization policy 'constraints/{constraint}' should be enforced on this project "
           "so the related misconfiguration cannot be introduced.",
           f"Console > IAM & Admin > Organization Policies: enforce constraints/{constraint} "
           "at the organization or folder (gcloud org-policies set-policy).")
    def fn(ctx):
        pol = ctx.effective_org_policy(constraint)
        rules = (pol.get("spec") or {}).get("rules", []) or []
        if kind == "list":   # list constraint: an allow-list must be configured
            enforced = any((r.get("values") or {}).get("allowedValues") for r in rules)
        else:
            enforced = any(r.get("enforce") is True or r.get("denyAll") is True for r in rules)
        return passed(f"constraints/{constraint} is enforced") if enforced else failed(
            f"constraints/{constraint} is not enforced", [constraint])
    return fn


for _spec in _ORG_POLICIES:
    _make_org_policy_check(*_spec)


# --------------------------------------------------------------------------- #
# Separation of duties (1.8 / 1.11) - evaluated across project + inherited policies
# --------------------------------------------------------------------------- #
def _policies(ctx):
    """The scope's own IAM policy plus every readable ancestor policy."""
    inherited, _notes = ctx.inherited_policies()
    return [ctx.iam_policy()] + [p for _label, p in inherited]


def _holders(policies, roles):
    out = set()
    for pol in policies:
        for b in pol.get("bindings", []) or []:
            if b.get("role") in roles:
                out.update(b.get("members", []))
    return out


def _sod(ctx, roles_a, roles_b):
    pols = _policies(ctx)
    return sorted(_holders(pols, roles_a) & _holders(pols, roles_b))


@check("1.8", "Separation of duties: no principal holds both Service Account Admin and Service Account User",
       SEC_IAM, 2, "Medium",
       "A principal that can both create service accounts and impersonate them can escalate privileges. "
       "Evaluated across the project and all readable ancestors. Group membership is not expanded.",
       "Remove one of roles/iam.serviceAccountAdmin or roles/iam.serviceAccountUser from each listed principal.")
def c_1_8(ctx):
    bad = _sod(ctx, {"roles/iam.serviceAccountAdmin"}, {"roles/iam.serviceAccountUser"})
    return failed("Principals hold both roles", bad) if bad else passed("No principal holds both roles")


_KMS_USE = {"roles/cloudkms.cryptoKeyEncrypterDecrypter", "roles/cloudkms.cryptoKeyEncrypter",
            "roles/cloudkms.cryptoKeyDecrypter"}


@check("1.11", "Separation of duties: no principal holds Cloud KMS Admin and encrypt/decrypt roles", SEC_IAM, 2,
       "Medium",
       "A KMS administrator who can also use keys can read data they should only be able to manage. "
       "Evaluated across the project and all readable ancestors. Group membership is not expanded.",
       "Remove roles/cloudkms.admin or the cryptoKey encrypt/decrypt roles from each listed principal.")
def c_1_11(ctx):
    bad = _sod(ctx, {"roles/cloudkms.admin"}, _KMS_USE)
    return failed("Principals hold KMS admin and key-use roles", bad) if bad else passed(
        "No principal combines KMS admin with key-use roles")


# --------------------------------------------------------------------------- #
# Additional benchmark checks
# --------------------------------------------------------------------------- #
@check("2.12", "Cloud DNS logging is enabled for all VPC networks", SEC_LOG, 1, "Medium",
       "DNS query logs support detection of data exfiltration and malware command-and-control.",
       "Create a DNS policy with logging enabled and attach it to each VPC: "
       "gcloud dns policies create P --networks=N --enable-logging --description=...")
def c_2_12(ctx):
    nets = ctx.networks()
    logged = {short(n.get("networkUrl", "")) for p in ctx.dns_policies() if p.get("enableLogging")
              for n in p.get("networks", []) or []}
    return evaluate(len(nets), [n["name"] for n in nets if n["name"] not in logged], "VPC networks")


@check("2.16", "Logging is enabled for HTTP(S) load balancer backend services", SEC_LOG, 2, "Medium",
       "Load balancer logs record requests for security analysis and troubleshooting.",
       "gcloud compute backend-services update BACKEND --global --enable-logging --logging-sample-rate=1.0")
def c_2_16(ctx):
    bs = ctx.backend_services()
    bad = [b["name"] for b in bs if not (b.get("logConfig") or {}).get("enable")]
    return evaluate(len(bs), bad, "backend services")


@check("3.9", "HTTPS/SSL proxy load balancers use an SSL policy without weak ciphers", SEC_NET, 1, "Medium",
       "Without a restrictive SSL policy, proxies accept legacy TLS versions and weak cipher suites.",
       "Create an SSL policy (--min-tls-version=1.2 --profile=MODERN or RESTRICTED) and attach it to each proxy.")
def c_3_9(ctx):
    proxies = ctx.tls_proxies()
    if not proxies:
        return not_applicable("No HTTPS or SSL proxy load balancers in this project")
    policies = {p["name"]: p for p in ctx.ssl_policies()}
    bad = []
    for px in proxies:
        ref = short(px.get("sslPolicy", ""))
        pol = policies.get(ref)
        if not ref:
            bad.append(f"{px['name']}: no SSL policy (Google default allows TLS 1.0)")
        elif pol and (pol.get("minTlsVersion") in (None, "TLS_1_0", "TLS_1_1")
                      or pol.get("profile") == "COMPATIBLE"):
            bad.append(f"{px['name']}: policy '{ref}' allows TLS<1.2 or the COMPATIBLE profile")
    return evaluate(len(proxies), bad, "TLS proxies")


@check("4.7", "VM disks are encrypted with Customer-Supplied Encryption Keys (CSEK)", SEC_VM, 2, "Medium",
       "CIS asks for CSEK on disks of critical VMs. Critical VMs cannot be identified through the API, so "
       "ALL disks are evaluated: CMEK-only and Google-managed disks are reported, and you should filter "
       "the list to your critical workloads.",
       "Re-create the disk from a snapshot with --csek-key-file.")
def c_4_7(ctx):
    disks = ctx.disks()
    bad = []
    for d in disks:
        key = d.get("diskEncryptionKey") or {}
        if not key.get("sha256"):
            kind = "CMEK (not CSEK)" if key.get("kmsKeyName") else "Google-managed key"
            bad.append(f"{d['name']} ({short(d.get('zone', ''))}): {kind}")
    return evaluate(len(disks), bad, "disks")


@check("4.11", "Compute instances are launched with Confidential VM enabled", SEC_VM, 2, "Low",
       "Confidential VMs encrypt data in use. Only supported machine families (e.g. N2D, C2D) can enable it.",
       "Create the instance with --confidential-compute on a supported machine type.")
def c_4_11(ctx):
    vms = _vms(ctx)
    bad = [inst_name(i) for i in vms
           if not (i.get("confidentialInstanceConfig") or {}).get("enableConfidentialCompute")]
    return evaluate(len(vms), bad, "VM instances")


@check("7.2", "BigQuery tables are encrypted with customer-managed keys", SEC_BQ, 2, "Medium",
       "CMEK gives control over key lifecycle for table data at rest. At most 200 tables are inspected.",
       "bq cp -f --destination_kms_key KEY SRC DST, or set a dataset default key (7.3).")
def c_7_2(ctx):
    tables, truncated = ctx.bq_tables()
    bad = [t["_label"] for t in tables if not (t.get("encryptionConfiguration") or {}).get("kmsKeyName")]
    out = evaluate(len(tables), bad, "tables")
    if truncated:
        out.message += " (stopped at the 200-table inspection limit)"
    return out


# --------------------------------------------------------------------------- #
# 11 - Organization level (run once per organization found in the project hierarchy)
# --------------------------------------------------------------------------- #
def _org_check(cid, title, severity, desc, rem, fn):
    check(cid, title, SEC_ORG, 1 if severity == "High" else 2, severity, desc, rem, scope="org")(fn)


_org_check("11.1", "Org IAM: no personal @gmail.com accounts hold organization roles", "Medium",
           "Personal accounts at organization level are unmanaged and may persist after offboarding.",
           "Replace user:*@gmail.com members with managed corporate identities.", c_1_1)
_org_check("11.2", "Org IAM: service accounts do not hold admin roles at organization level", "High",
           "An admin service account at organization level can compromise every project.",
           "Remove Owner/Editor/*Admin roles from service accounts at organization scope.", c_1_5)
_org_check("11.3", "Org IAM: no Service Account User / Token Creator granted at organization level", "High",
           "These roles at organization level allow impersonating any service account in the organization.",
           "Grant them on individual service accounts or projects instead.", c_1_6)
_org_check("11.4", "Org IAM: separation of duties for Service Account Admin / User", "Medium",
           "No principal should hold both roles (group membership is not expanded).",
           "Split roles/iam.serviceAccountAdmin and roles/iam.serviceAccountUser across principals.", c_1_8)
_org_check("11.5", "Org IAM: separation of duties for Cloud KMS Admin and key-use roles", "Medium",
           "No principal should hold Cloud KMS Admin together with encrypt/decrypt roles.",
           "Split roles/cloudkms.admin from the cryptoKey encrypt/decrypt roles.", c_1_11)
_org_check("11.6", "Org audit logging covers all services with no exemptions", "High",
           "Organization-level audit config applies to every project underneath.",
           "Set an organization-level auditConfig for allServices with ADMIN_READ, DATA_READ, DATA_WRITE "
           "and no exemptedMembers.", c_2_1)


def c_11_7(ctx):
    sinks = ctx.sinks()
    good = [s["name"] for s in sinks if s.get("includeChildren") and not s.get("filter")
            and not s.get("exclusions") and not s.get("disabled")]
    return passed("Aggregated catch-all sink(s): " + ", ".join(good)) if good else failed(
        "No enabled aggregated sink (includeChildren, no filter/exclusions) at organization level",
        [s["name"] for s in sinks])


_org_check("11.7", "Org-level aggregated log sink exports all logs from child resources", "Medium",
           "An aggregated sink preserves logs for every project, even ones created later.",
           "gcloud logging sinks create NAME DEST --organization=ID --include-children", c_11_7)


def c_11_8(ctx):
    need = {"LEGAL", "SECURITY", "SUSPENSION", "TECHNICAL"}
    have = set()
    for c in ctx.essential_contacts():
        cats = set(c.get("notificationCategorySubscriptions", []) or [])
        have |= need if "ALL" in cats else cats
    missing = sorted(need - have)
    return failed("Essential Contacts missing categories", missing) if missing else passed(
        "Legal, Security, Suspension and Technical contacts are configured")


_org_check("11.8", "Essential Contacts are configured for Legal, Security, Suspension and Technical", "Low",
           "Google sends security and legal notices only to configured contacts.",
           "Console > IAM & Admin > Essential Contacts: add contacts for the four categories.", c_11_8)


def c_11_9(ctx):
    rules = (ctx.org_policy("iam.allowedPolicyMemberDomains").get("spec") or {}).get("rules", []) or []
    ok = any((r.get("values") or {}).get("allowedValues") for r in rules)
    return passed("Domain-restricted sharing is configured") if ok else failed(
        "constraints/iam.allowedPolicyMemberDomains has no allow-list", ["iam.allowedPolicyMemberDomains"])


_org_check("11.9", "Org policy: domain-restricted sharing is configured at organization level", "High",
           "Restricts IAM grants to identities from approved domains, blocking accidental external sharing.",
           "Set constraints/iam.allowedPolicyMemberDomains with your Cloud Identity customer ID(s).", c_11_9)
