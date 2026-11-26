import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gcp_cis_audit import report
from gcp_cis_audit.checks import _port_open, age_days
from gcp_cis_audit.client import ApiError, BaseClient
from gcp_cis_audit.demo import DemoClient
from gcp_cis_audit.runner import all_checks, run_audit, select_checks, summarize


def by_id(results, project="demo-prod"):
    return {r.check_id: r for r in results if r.project == project}


class DemoAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = run_audit(DemoClient(), ["demo-prod", "demo-empty"], select_checks())
        cls.prod = by_id(cls.results)

    def test_every_check_produces_a_result(self):
        self.assertEqual(len(self.results), 2 * len(all_checks()))

    def test_no_unexpected_errors_in_demo(self):
        errs = [(r.project, r.check_id, r.message) for r in self.results if r.status == "ERROR"]
        self.assertEqual(errs, [])

    def test_expected_failures(self):
        for cid in ("1.1", "1.4", "1.5", "1.6", "1.7", "1.9", "1.10", "2.1", "2.3", "2.13", "3.1", "3.3",
                    "3.6", "3.8", "4.1", "4.2", "4.3", "4.6", "4.9", "5.1", "5.2", "6.4", "6.5", "6.6",
                    "6.7", "7.1", "7.3"):
            self.assertEqual(self.prod[cid].status, "FAIL", cid)

    def test_expected_passes(self):
        for cid in ("3.2", "3.7", "2.7"):
            self.assertEqual(self.prod[cid].status, "PASS", cid)

    def test_log_metric_check_needs_matching_metric(self):
        self.assertEqual(self.prod["2.4"].status, "FAIL")  # no ownership metric in demo data

    def test_manual_checks(self):
        self.assertEqual(self.prod["1.2"].status, "MANUAL")

    def test_empty_project_is_not_applicable_not_error(self):
        empty = by_id(self.results, "demo-empty")
        self.assertEqual(empty["4.1"].status, "N/A")
        self.assertEqual(empty["5.1"].status, "N/A")

    def test_summary_score(self):
        s = summarize(self.results)
        self.assertEqual(sum(s["counts"].values()), len(self.results))
        self.assertTrue(0 <= s["score"] <= 100)


class ExtendedCoverageTests(unittest.TestCase):
    """Org/folder inheritance, org policy, GKE, Dataproc, API keys and SQL flags."""

    @classmethod
    def setUpClass(cls):
        cls.results = run_audit(DemoClient(), ["demo-prod", "demo-empty"], select_checks())
        cls.prod = by_id(cls.results)
        cls.empty = by_id(cls.results, "demo-empty")

    def test_aggregated_org_sink_satisfies_2_2(self):
        self.assertEqual(self.prod["2.2"].status, "PASS")
        self.assertIn("aggregated", self.prod["2.2"].message)

    def test_audit_config_inherited_but_exemption_still_fails_2_1(self):
        r = self.prod["2.1"]
        self.assertEqual(r.status, "FAIL")
        # DATA_WRITE is missing at project level but supplied by the org, so only the exemption remains.
        self.assertFalse(any("missing" in x for x in r.resources), r.resources)
        self.assertTrue(any("Exempted" in x for x in r.resources), r.resources)

    def test_org_policies(self):
        self.assertEqual(self.prod["10.1"].status, "PASS")
        self.assertEqual(self.prod["10.3"].status, "PASS")
        self.assertEqual(self.prod["10.2"].status, "FAIL")
        self.assertEqual(self.empty["10.2"].status, "N/A")

    def test_gke(self):
        self.assertEqual(self.prod["8.1"].resources, ["legacy-cluster (us-central1-a)"])
        for cid in ("8.2", "8.4", "8.5", "8.6", "8.8", "8.9", "8.10", "8.11", "8.12", "8.13"):
            self.assertEqual(self.prod[cid].status, "FAIL", cid)
            self.assertNotIn("hardened-cluster (us-east1)", self.prod[cid].resources, cid)
        self.assertEqual(self.empty["8.1"].status, "N/A")

    def test_dataproc(self):
        self.assertEqual(self.prod["9.1"].status, "FAIL")
        self.assertEqual(self.prod["9.2"].status, "FAIL")
        self.assertEqual(self.empty["9.1"].status, "N/A")

    def test_api_keys(self):
        for cid in ("1.12", "1.13", "1.14", "1.15"):
            self.assertEqual(self.prod[cid].status, "FAIL", cid)

    def test_sql_flags_respect_engine_and_defaults(self):
        self.assertEqual(self.prod["6.1.2"].status, "FAIL")      # explicitly 'off'
        self.assertEqual(self.prod["6.1.3"].status, "FAIL")      # unset -> engine default 'on'
        self.assertIn("engine default", self.prod["6.1.3"].resources[0])
        for cid in ("6.2.1", "6.2.2", "6.2.3", "6.2.7", "6.2.8", "6.3.1", "6.3.2", "6.3.3", "6.3.4"):
            self.assertEqual(self.prod[cid].status, "PASS", cid)
        self.assertEqual(self.prod["6.3.5"].status, "FAIL")      # SQL Server remote access defaults on
        self.assertEqual(self.prod["6.3.5"].resources, ["erp-mssql: remote access='on' (engine default)"])

    def test_inheritance_makes_project_with_no_audit_config_pass(self):
        class OrgOnly(DemoClient):
            def _request(self, method, url, params=None, body=None):
                if url.endswith("projects/demo-prod:getIamPolicy"):
                    return {"bindings": []}
                return super()._request(method, url, params, body)
        res = by_id(run_audit(OrgOnly(), ["demo-prod"], select_checks(["2 - Logging & Monitoring"])))
        self.assertEqual(res["2.1"].status, "PASS")
        self.assertIn("inherited", res["2.1"].message)

    def test_unreadable_ancestors_are_reported_not_hidden(self):
        class NoOrgAccess(DemoClient):
            def _request(self, method, url, params=None, body=None):
                if "/organizations/" in url or "/folders/" in url:
                    raise ApiError(403, "The caller does not have permission", url)
                return super()._request(method, url, params, body)
        res = by_id(run_audit(NoOrgAccess(), ["demo-prod"], select_checks(["2 - Logging & Monitoring"])))
        self.assertEqual(res["2.1"].status, "FAIL")
        self.assertTrue(any("Not evaluated" in x for x in res["2.1"].resources), res["2.1"].resources)
        self.assertEqual(res["2.2"].status, "FAIL")  # no visible catch-all sink once org sinks are unreadable
        self.assertTrue(any("Not evaluated" in x for x in res["2.2"].resources))

    def test_permission_error_is_error_not_crash(self):
        class Denied(DemoClient):
            def _request(self, method, url, params=None, body=None):
                if "container.googleapis.com" in url:
                    raise ApiError(403, "Permission denied", url)
                return super()._request(method, url, params, body)
        res = by_id(run_audit(Denied(), ["demo-prod"], select_checks(["8 - GKE"])))
        self.assertTrue(all(r.status == "ERROR" for r in res.values()))


class HelperTests(unittest.TestCase):
    def test_port_ranges(self):
        self.assertTrue(_port_open([{"IPProtocol": "tcp", "ports": ["20-30"]}], 22))
        self.assertTrue(_port_open([{"IPProtocol": "tcp"}], 3389))
        self.assertTrue(_port_open([{"IPProtocol": "all"}], 22))
        self.assertFalse(_port_open([{"IPProtocol": "udp", "ports": ["22"]}], 22))
        self.assertFalse(_port_open([{"IPProtocol": "tcp", "ports": ["2200"]}], 22))

    def test_age_days_handles_fractional_seconds(self):
        self.assertGreater(age_days("2020-01-01T00:00:00.123456789Z"), 365)

    def test_pagination(self):
        class C(BaseClient):
            def _request(self, m, url, params=None, body=None):
                return {"x": [1], "nextPageToken": "t"} if not (params or {}).get("pageToken") else {"x": [2]}
        self.assertEqual(C().list("u", "x"), [1, 2])

    def test_service_disabled_detection(self):
        self.assertTrue(ApiError(403, "Compute Engine API has not been used in project 1").service_disabled)
        self.assertFalse(ApiError(403, "Permission denied").service_disabled)


class ReportTests(unittest.TestCase):
    def test_exports(self):
        res = run_audit(DemoClient(), ["demo-prod"], select_checks())
        with tempfile.TemporaryDirectory() as d:
            for name, fn in (("a.json", report.to_json), ("a.csv", report.to_csv), ("a.html", report.to_html)):
                p = os.path.join(d, name)
                fn(res, p)
                self.assertGreater(os.path.getsize(p), 100)


if __name__ == "__main__":
    unittest.main()
