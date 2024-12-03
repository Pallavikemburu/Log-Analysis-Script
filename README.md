# Log-Analysis-Script

Overview
Python script for analyzing web server logs, focusing on IP request tracking, endpoint access, and suspicious activity detection.
Features

IP request counting
Endpoint access analysis
Suspicious login attempt detection
CSV report generation

Prerequisites

Python 3.x
Standard library modules (re, csv, collections)

Usage
bashCopypython log_analysis_script.py
Key Functionalities

Parses log files
Tracks request counts per IP
Identifies most accessed endpoint
Detects potential brute force attempts

Output

Terminal display of analysis results
log_analysis_results.csv with detailed findings

Customization
Adjustable failed login attempt threshold in analyze_log_file() function.
License
MIT License
