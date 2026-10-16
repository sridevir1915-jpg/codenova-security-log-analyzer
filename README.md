# Security Log Analyzer & Incident Detection Engine

A lightweight security auditing tool designed to parse authentication server logs, identify high-frequency failed login attempts (brute-force attacks), detect off-hours anomalous access, and generate structured Markdown incident reports. Developed for the **CodeNova Cybersecurity Remote Internship Program (Batch 01)**.

---

## Key Features

- **Log Parsing & Regex**: Uses regular expressions to extract timestamps, authentication status (`FAIL`/`SUCCESS`), usernames, and source IP addresses.
- **Brute-Force Detection**: Flags source IP addresses that exceed configurable failure thresholds (e.g., $\ge 5$ failed attempts).
- **Off-Hours Anomaly Flags**: Detects successful logins occurring during sensitive off-hours windows (12 AM – 5 AM).
- **Automated Incident Reports**: Exports formatted Markdown incident reports (`security_report.md`) featuring summary tables and threat level tags.

---

## Tech Stack & Tooling

- **Language**: Python 3
- **Core Modules**: `re`, `os`, `collections`, `datetime`, `unittest`

---

## Project Structure

```text
codenova-security-log-analyzer/
├── analyzer.py         # Core log parsing and report generator script
├── test_analyzer.py    # Unit test suite validating detection logic
├── sample_auth.log     # Synthetic authentication log dataset
├── security_report.md  # Generated security incident report
├── README.md           # Technical project documentation
└── .gitignore          # Ignores runtime cache and temporary test logs
```

---

## How to Run

### 1. Execute the Log Analyzer
Run the script to analyze the sample authentication log and export the incident report:

```cmd
python analyzer.py
```

### 2. Run the Unit Test Suite
Execute unit tests to verify detection logic against synthetic test vectors:

```cmd
python -m unittest test_analyzer.py
```

---

## Certificate & Internship Specifications

- **Program**: CodeNova Cybersecurity Remote Internship (Batch 01)
- **Task**: Task 4 - Security Log Analyzer
- **Submission Deadline**: 06 November 2026