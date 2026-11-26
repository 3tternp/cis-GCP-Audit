"""Offline demo client: serves canned, deliberately misconfigured GCP API data.

Used by the GUI's "Demo mode" checkbox, ``--demo`` on the CLI and the unit tests,
so the tool can be tried without any GCP credentials.
"""
from __future__ import annotations

import re

from .client import ApiError, BaseClient

DEMO_PROJECTS = ["demo-prod", "demo-empty"]
_P = "demo-prod"
_SA = f"ci-deployer@{_P}.iam.gserviceaccount.com"
_KEY = f"projects/{_P}/serviceAccounts/{_SA}/keys/0123456789abcdef"
_KMS_KEY = f"projects/{_P}/locations/global/keyRings/ring1/cryptoKeys/key1"

_VMS = {"items": {"zones/us-central1-a": {"instances": [
    {"name": "web-1", "zone": "zones/us-central1-a", "canIpForward": True,
     "metadata": {"items": []},
     "serviceAccounts": [{"email": "1234-compute@developer.gserviceaccount.com",
                          "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}],
     "networkInterfaces": [{"accessConfigs": [{"natIP": "34.1.2.3"}]}],
     "shieldedInstanceConfig": {"enableVtpm": False, "enableIntegrityMonitoring": False}},
    {"name": "batch-1", "zone": "zones/us-central1-a", "canIpForward": False,
     "metadata": {"items": [{"key": "block-project-ssh-keys", "value": "TRUE"},
                            {"key": "serial-port-enable", "value": "FALSE"}]},
     "serviceAccounts": [{"email": f"worker@{_P}.iam.gserviceaccount.com", "scopes": []}],
     "networkInterfaces": [{}],
     "shieldedInstanceConfig": {"enableVtpm": True, "enableIntegrityMonitoring": True}},
]}}}

def _org_iam(u, b):
    # Organization grants DATA_WRITE audit logging; the folder adds nothing.
    if "/organizations/" in u:
        return {"auditConfigs": [{"service": "allServices", "auditLogConfigs": [
            {"logType": "ADMIN_READ"}, {"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}]}]}
    return {}


_ENFORCED_POLICIES = ("compute.requireOsLogin", "compute.skipDefaultNetworkCreation")


def _org_policy(u, b):
    name = u.split("/policies/")[1].split(":")[0]
    if name in _ENFORCED_POLICIES:
        return {"spec": {"rules": [{"enforce": True}]}}
    return {"spec": {"rules": [{"enforce": False}]}}


_GKE = {"clusters": [
    {"name": "legacy-cluster", "location": "us-central1-a", "loggingService": "none",
     "monitoringService": "none", "legacyAbac": {"enabled": True},
     "masterAuth": {"clientCertificateConfig": {"issueClientCertificate": True}},
     "nodePools": [{"name": "default-pool", "management": {"autoUpgrade": False},
                    "config": {"imageType": "UBUNTU", "serviceAccount": "default"}}]},
    {"name": "hardened-cluster", "location": "us-east1",
     "privateClusterConfig": {"enablePrivateNodes": True},
     "masterAuthorizedNetworksConfig": {"enabled": True},
     "networkConfig": {"datapathProvider": "ADVANCED_DATAPATH"},
     "loggingService": "logging.googleapis.com/kubernetes",
     "monitoringService": "monitoring.googleapis.com/kubernetes",
     "workloadIdentityConfig": {"workloadPool": f"{_P}.svc.id.goog"},
     "shieldedNodes": {"enabled": True}, "releaseChannel": {"channel": "REGULAR"},
     "nodePools": [{"name": "pool", "management": {"autoUpgrade": True},
                    "config": {"imageType": "COS_CONTAINERD",
                               "serviceAccount": f"gke-nodes@{_P}.iam.gserviceaccount.com"}}]},
]}

_SQL = {"items": [
    {"name": "orders-db", "databaseVersion": "MYSQL_8_0", "settings": {
        "databaseFlags": [{"name": "skip_show_database", "value": "off"}],
        "ipConfiguration": {"ipv4Enabled": True, "requireSsl": False,
                            "authorizedNetworks": [{"value": "0.0.0.0/0"}]},
        "backupConfiguration": {"enabled": False}}},
    {"name": "ledger-pg", "databaseVersion": "POSTGRES_15", "settings": {
        "databaseFlags": [{"name": "log_connections", "value": "on"},
                          {"name": "log_disconnections", "value": "on"},
                          {"name": "cloudsql.enable_pgaudit", "value": "on"}],
        "ipConfiguration": {"ipv4Enabled": False, "sslMode": "ENCRYPTED_ONLY"},
        "backupConfiguration": {"enabled": True}}},
    {"name": "erp-mssql", "databaseVersion": "SQLSERVER_2019_STANDARD", "settings": {
        "ipConfiguration": {"ipv4Enabled": False, "sslMode": "ENCRYPTED_ONLY"},
        "backupConfiguration": {"enabled": True}}},
]}

_ROUTES = [
    (r"(organizations|folders)/\d+:getIamPolicy$", _org_iam),
    (r":getAncestry$", lambda u, b: {"ancestor": [
        {"resourceId": {"type": "project", "id": _P}},
        {"resourceId": {"type": "folder", "id": "111"}},
        {"resourceId": {"type": "organization", "id": "999"}}]}),
    (r"/organizations/\d+/sinks$", lambda u, b: {"sinks": [
        {"name": "org-archive", "destination": "storage.googleapis.com/org-logs", "includeChildren": True}]}),
    (r"/folders/\d+/sinks$", lambda u, b: {}),
    (r"orgpolicy.googleapis.com", _org_policy),
    (r"container.googleapis.com", lambda u, b: _GKE),
    (r"compute/v1/projects/[^/]+/regions$", lambda u, b: {"items": [{"name": "us-central1"}]}),
    (r"dataproc.googleapis.com.*/clusters$", lambda u, b: {"clusters": [
        {"clusterName": "etl", "config": {"gceClusterConfig": {"internalIpOnly": False},
                                           "encryptionConfig": {}}}]}),
    (r"apikeys.googleapis.com", lambda u, b: {"keys": [
        {"name": f"projects/1/locations/global/keys/k1", "displayName": "maps-browser",
         "createTime": "2022-01-01T00:00:00Z", "restrictions": {}}]}),
    (r":getIamPolicy$", lambda u, b: {
        "bindings": [
            {"role": "roles/owner", "members": ["user:admin@corp.example"]},
            {"role": "roles/editor", "members": ["user:bob@gmail.com", f"serviceAccount:{_SA}"]},
            {"role": "roles/iam.serviceAccountUser", "members": ["user:alice@corp.example"]}],
        "auditConfigs": [{"service": "allServices", "auditLogConfigs": [
            {"logType": "ADMIN_READ"},
            {"logType": "DATA_READ", "exemptedMembers": ["user:svc@corp.example"]}]}]}
     if "/projects/" in u and "cloudkms" not in u else {"bindings": [
         {"role": "roles/cloudkms.cryptoKeyDecrypter", "members": ["allUsers"]}]}),
    (r"/serviceAccounts/[^/]+/keys", lambda u, b: {"keys": [
        {"name": _KEY, "validAfterTime": "2023-01-01T00:00:00Z"}]}),
    (r"/serviceAccounts$", lambda u, b: {"accounts": [{"name": f"projects/{_P}/serviceAccounts/{_SA}",
                                                       "email": _SA}]}),
    (r"cloudkms.*/locations$", lambda u, b: {"locations": [{"locationId": "global"}]}),
    (r"/keyRings$", lambda u, b: {"keyRings": [{"name": f"projects/{_P}/locations/global/keyRings/ring1"}]}),
    (r"/cryptoKeys$", lambda u, b: {"cryptoKeys": [{"name": _KMS_KEY, "purpose": "ENCRYPT_DECRYPT"}]}),
    (r"/sinks$", lambda u, b: {"sinks": [{"name": "audit-only", "filter": "logName:cloudaudit",
                                         "destination": "storage.googleapis.com/log-archive"}]}),
    (r"/storage/v1/b/log-archive$", lambda u, b: {"name": "log-archive"}),
    (r"/metrics$", lambda u, b: {"metrics": [{"name": "fw-change", "filter":
        'resource.type="gce_firewall_rule" AND (protoPayload.methodName:"compute.firewalls.patch" OR '
        'protoPayload.methodName:"compute.firewalls.insert" OR protoPayload.methodName:"compute.firewalls.delete")'}]}),
    (r"/alertPolicies$", lambda u, b: {"alertPolicies": [{"displayName": "Firewall changed", "enabled": True,
        "conditions": [{"conditionThreshold": {"filter":
            'metric.type="logging.googleapis.com/user/fw-change" resource.type="global"'}}]}]}),
    (r"services/cloudasset", lambda u, b: {"state": "DISABLED"}),
    (r"/aggregated/instances", lambda u, b: _VMS),
    (r"/aggregated/subnetworks", lambda u, b: {"items": {"regions/us-central1": {"subnetworks": [
        {"name": "subnet-a", "region": "regions/us-central1", "purpose": "PRIVATE", "logConfig": {"enable": False}},
        {"name": "subnet-b", "region": "regions/us-east1", "purpose": "PRIVATE", "logConfig": {"enable": True}}]}}}),
    (r"/global/firewalls", lambda u, b: {"items": [
        {"name": "allow-ssh-any", "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"],
         "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]},
        {"name": "allow-internal", "direction": "INGRESS", "sourceRanges": ["10.0.0.0/8"],
         "allowed": [{"IPProtocol": "all"}]}]}),
    (r"/global/networks", lambda u, b: {"items": [{"name": "default"}, {"name": "prod-vpc"}]}),
    (r"/managedZones", lambda u, b: {"managedZones": [
        {"name": "example-com", "visibility": "public", "dnssecConfig": {"state": "off"}}]}),
    (r"compute/v1/projects/[^/]+$", lambda u, b: {"commonInstanceMetadata": {"items": []}}),
    (r"/storage/v1/b/[^/]+/iam$", lambda u, b: {"bindings": [{"role": "roles/storage.objectViewer",
        "members": ["allUsers"]}]} if "public-assets" in u else {"bindings": []}),
    (r"/storage/v1/b$", lambda u, b: {"items": [
        {"name": "public-assets", "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": False}}},
        {"name": "private-data", "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}}}]}),
    (r"sqladmin.*/instances$", lambda u, b: _SQL),
    (r"/datasets/[^/]+$", lambda u, b: {"datasetReference": {"datasetId": "analytics"},
        "access": [{"role": "READER", "specialGroup": "allAuthenticatedUsers"}]}),
    (r"/datasets$", lambda u, b: {"datasets": [{"datasetReference": {"datasetId": "analytics"}}]}),
    (r"cloudresourcemanager.*/projects$", lambda u, b: {"projects": [{"projectId": p} for p in DEMO_PROJECTS]}),
]


class DemoClient(BaseClient):
    def _request(self, method, url, params=None, body=None):
        if "demo-empty" in url or (params or {}).get("project") == "demo-empty":
            if "getIamPolicy" in url:
                return {}
            raise ApiError(403, "API has not been used in project SERVICE_DISABLED", url)
        for pattern, handler in _ROUTES:
            if re.search(pattern, url):
                return handler(url, body)
        raise ApiError(404, f"No demo data for {url}", url)

    def discover_projects(self):
        return list(DEMO_PROJECTS)
