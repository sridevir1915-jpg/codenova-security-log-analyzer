# Security Incident Analysis Report

**Log File Analyzed**: `sample_auth.log`  
**Analysis Timestamp**: `2026-10-16 11:16:34`  
**Brute-Force Threshold**: `5 failed attempts`  

--- 

## 1. Failed Login Tallies per IP

| Source IP Address | Failed Attempts | Risk Status |
|-------------------|-----------------|-------------|
| `192.168.1.100` | `6` | CRITICAL (Brute-Force) |
| `172.16.0.22` | `1` | Normal |


## 2. Brute-Force Threshold Violations

- **CRITICAL ALERT**: IP `192.168.1.100` exceeded threshold with **6** failed login attempts.


## 3. Detected Anomalies & Off-Hours Activity

- **[HIGH] Off-Hours Login**: User 'root' logged in from IP 10.0.0.50 at 2026-10-16 03:22:01
