import unittest
import os
from analyzer import SecurityLogAnalyzer

class TestSecurityLogAnalyzer(unittest.TestCase):
    def setUp(self):
        self.test_log = "test_auth.log"
        self.test_report = "test_report.md"
        
        with open(self.test_log, "w", encoding="utf-8") as f:
            for _ in range(6):
                f.write("2026-10-16 10:00:00 auth.log FAIL login user=admin ip=192.168.1.100\n")
            f.write("2026-10-16 02:30:00 auth.log SUCCESS login user=root ip=10.0.0.5\n")

        self.analyzer = SecurityLogAnalyzer(self.test_log, failure_threshold=5, report_filepath=self.test_report)
        self.analyzer.parse_log()

    def tearDown(self):
        if os.path.exists(self.test_log):
            os.remove(self.test_log)
        if os.path.exists(self.test_report):
            os.remove(self.test_report)

    def test_brute_force_flagging(self):
        brute_force_ips = {ip: count for ip, count in self.analyzer.failed_attempts.items() if count >= self.analyzer.failure_threshold}
        self.assertIn("192.168.1.100", brute_force_ips)
        self.assertEqual(brute_force_ips["192.168.1.100"], 6)

    def test_off_hours_anomaly(self):
        self.assertTrue(len(self.analyzer.anomalies) > 0)

    def test_markdown_report_creation(self):
        brute_force_ips = {ip: count for ip, count in self.analyzer.failed_attempts.items() if count >= self.analyzer.failure_threshold}
        self.analyzer.export_markdown_report(brute_force_ips)
        self.assertTrue(os.path.exists(self.test_report))

if __name__ == "__main__":
    unittest.main()