import unittest
import os
from analyzer import SecurityLogAnalyzer

class TestSecurityLogAnalyzer(unittest.TestCase):
    def setUp(self):
        self.test_log = "test_auth.log"
        self.test_report = "test_report.md"
        
        with open(self.test_log, "w", encoding="utf-8") as f:
            # 6 failed attempts from 192.168.1.100 (triggers brute force threshold)
            for _ in range(6):
                f.write("2026-10-16 10:00:00 auth.log FAIL login user=admin ip=192.168.1.100\n")
            # 1 off-hours success
            f.write("2026-10-16 02:30:00 auth.log SUCCESS login user=root ip=10.0.0.5\n")

        self.analyzer = SecurityLogAnalyzer(self.test_log, failure_threshold=5, report_filepath=self.test_report)

    def tearDown(self):
        if os.path.exists(self.test_log):
            os.remove(self.test_log)
        if os.path.exists(self.test_report):
            os.remove(self.test_report)

    def test_brute_force_flagging(self):
        res = self.analyzer.run_analysis()
        self.assertIn("192.168.1.100", res["brute_force_ips"])
        self.assertEqual(res["brute_force_ips"]["192.168.1.100"], 6)

    def test_off_hours_anomaly(self):
        res = self.analyzer.run_analysis()
        self.assertTrue(len(res["anomalies"]) > 0)

    def test_markdown_report_creation(self):
        self.analyzer.run_analysis()
        self.assertTrue(os.path.exists(self.test_report))

if __name__ == "__main__":
    unittest.main()