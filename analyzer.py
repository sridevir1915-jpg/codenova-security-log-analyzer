import re
import os
from collections import defaultdict
from datetime import datetime

class SecurityLogAnalyzer:
    def __init__(self, log_filepath, failure_threshold=5, report_filepath="security_report.md"):
        self.log_filepath = log_filepath
        self.report_filepath = report_filepath
        self.failure_threshold = failure_threshold
        self.failed_attempts = defaultdict(int)
        self.user_failures = defaultdict(int)
        self.successful_logins = []
        self.anomalies = []

    def parse_log(self):
        """Parses authentication logs for failed attempts and anomalous patterns."""
        log_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \S+ (FAIL|SUCCESS) login user=(\w+) ip=([\d\.]+)'
        
        if not os.path.exists(self.log_filepath):
            print(f"[-] Error: Log file '{self.log_filepath}' not found.")
            return

        with open(self.log_filepath, "r", encoding="utf-8") as f:
            for line in f:
                match = re.search(log_pattern, line)
                if match:
                    timestamp_str, status, user, ip = match.groups()
                    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

                    if status == "FAIL":
                        self.failed_attempts[ip] += 1
                        self.user_failures[user] += 1
                    elif status == "SUCCESS":
                        self.successful_logins.append((timestamp, user, ip))
                        # Off-hours access detection (12 AM to 5 AM)
                        if 0 <= timestamp.hour < 5:
                            self.anomalies.append({
                                "type": "Off-Hours Login",
                                "severity": "HIGH",
                                "details": f"User '{user}' logged in from IP {ip} at {timestamp_str}"
                            })

    def export_markdown_report(self, brute_force_ips):
        """Generates a structured Security Incident Report in Markdown format."""
        with open(self.report_filepath, "w", encoding="utf-8") as f:
            f.write("# Security Incident Analysis Report\n\n")
            f.write(f"**Log File Analyzed**: `{self.log_filepath}`  \n")
            f.write(f"**Analysis Timestamp**: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`  \n")
            f.write(f"**Brute-Force Threshold**: `{self.failure_threshold} failed attempts`  \n\n")

            f.write("--- \n\n")
            f.write("## 1. Failed Login Tallies per IP\n\n")
            f.write("| Source IP Address | Failed Attempts | Risk Status |\n")
            f.write("|-------------------|-----------------|-------------|\n")
            for ip, count in self.failed_attempts.items():
                status = "CRITICAL (Brute-Force)" if count >= self.failure_threshold else "Normal"
                f.write(f"| `{ip}` | `{count}` | {status} |\n")

            f.write("\n\n## 2. Brute-Force Threshold Violations\n\n")
            if brute_force_ips:
                for ip, count in brute_force_ips.items():
                    f.write(f"- **CRITICAL ALERT**: IP `{ip}` exceeded threshold with **{count}** failed login attempts.\n")
            else:
                f.write("- No brute-force threshold violations detected.\n")

            f.write("\n\n## 3. Detected Anomalies & Off-Hours Activity\n\n")
            if self.anomalies:
                for anomaly in self.anomalies:
                    f.write(f"- **[{anomaly['severity']}] {anomaly['type']}**: {anomaly['details']}\n")
            else:
                f.write("- No off-hours anomalous logins detected.\n")

        print(f"\n[+] Security incident report exported successfully to '{self.report_filepath}'.")

    def run_analysis(self):
        """Runs log parsing and outputs summary to console."""
        self.parse_log()
        brute_force_ips = {ip: count for ip, count in self.failed_attempts.items() if count >= self.failure_threshold}

        print("==================================================")
        print("     SECURITY LOG ANALYZER - INCIDENT REPORT      ")
        print("==================================================")
        print(f"Log Analyzed     : {self.log_filepath}")
        print(f"Failed IP Count  : {len(self.failed_attempts)}")
        print(f"Flagged Attackers: {len(brute_force_ips)}")
        print(f"Anomalies Found  : {len(self.anomalies)}\n")

        print("[1] FAILED LOGIN TALLIES")
        for ip, count in self.failed_attempts.items():
            print(f" - IP {ip}: {count} failure(s)")

        print("\n[2] BRUTE-FORCE THREAT FLAGS")
        if brute_force_ips:
            for ip, count in brute_force_ips.items():
                print(f" [CRITICAL] IP {ip} flagged for potential Brute-Force Attack ({count} failures)")
        else:
            print(" - No threshold violations.")

        print("\n[3] ANOMALOUS OFF-HOURS ACCESS")
        if self.anomalies:
            for a in self.anomalies:
                print(f" [{a['severity']}] {a['details']}")
        else:
            print(" - No off-hours anomalies.")

        self.export_markdown_report(brute_force_ips)

        return {
            "failed_attempts": dict(self.failed_attempts),
            "brute_force_ips": brute_force_ips,
            "anomalies": self.anomalies
        }

if __name__ == "__main__":
    analyzer = SecurityLogAnalyzer("sample_auth.log")
    analyzer.run_analysis()