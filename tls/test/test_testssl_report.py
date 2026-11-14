"""Grade evidence must remain strict while preserving explicit fixture scope."""
import unittest

from run_testssl import assess_report


def report(grade="A+", *extra, complete=True):
    return {"scanTime": 133 if complete else "Scan interrupted", "scanResult": [{
        "rating": [{"id": "overall_grade", "severity": "OK", "finding": grade}],
        "findings": list(extra)}]}


class TestsslReportEvidence(unittest.TestCase):
    def test_actual_grade_and_completion_are_required(self):
        self.assertTrue(assess_report(report())["passed"])
        self.assertFalse(assess_report(report("A-"))["passed"])
        self.assertFalse(assess_report(report(complete=False))["passed"])
        self.assertFalse(assess_report({"scanTime": 1})["passed"])

    def test_known_fixture_metadata_retains_high_severity(self):
        finding = {"id": "cert_revocation", "severity": "HIGH", "finding": "Neither CRL nor OCSP URI provided"}
        self.assertFalse(assess_report(report("A+", finding))["passed"])
        result = assess_report(report("A+", finding), generated_private_ca=True)
        self.assertTrue(result["passed"])
        self.assertEqual(result["fixture_certificate_limitations"], [finding])
        self.assertEqual(result["fixture_certificate_limitations"][0]["severity"], "HIGH")

    def test_client_capability_is_exact_not_a_blanket_warning_exception(self):
        finding = {"id": "engine_problem", "severity": "WARN", "finding": "No engine or GOST support via engine with your /test/openssl"}
        self.assertFalse(assess_report(report("A+", finding))["passed"])
        self.assertTrue(assess_report(report("A+", finding), client_openssl="/test/openssl")["passed"])
        changed = dict(finding, finding="Required protocol test unavailable")
        self.assertFalse(assess_report(report("A+", changed), client_openssl="/test/openssl")["passed"])

    def test_vulnerability_and_scan_errors_still_fail_with_known_limitations(self):
        for finding in ({"id": "heartbleed", "severity": "HIGH", "finding": "vulnerable"},
                        {"id": "scanProblem", "severity": "INFO", "finding": "a check could not complete"},
                        {"id": "other", "severity": "FATAL", "finding": "scanner failed"},
                        {"id": "cert_revocation", "severity": "HIGH", "finding": "certificate revoked"}):
            with self.subTest(finding=finding):
                self.assertFalse(assess_report(report("A+", finding), generated_private_ca=True,
                                               client_openssl="/test/openssl")["passed"])


if __name__ == "__main__":
    unittest.main()
