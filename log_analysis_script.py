import re
import csv
from collections import defaultdict

def parse_log_file(log_file_path):
    """
    Parse the log file and extract relevant information.
    
    Args:
        log_file_path (str): Path to the log file
    
    Returns:
        tuple: Containing dictionaries of IP requests, endpoints, and failed login attempts
    """
    ip_requests = defaultdict(int)
    endpoint_access = defaultdict(int)
    failed_login_attempts = defaultdict(int)

    with open(log_file_path, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                ip_requests[ip] += 1

            # Extract endpoint
            endpoint_match = re.search(r'"[A-Z]+ (/\w+)', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_access[endpoint] += 1

            # Detect failed login attempts
            if '401' in line and 'Invalid credentials' in line:
                failed_login_attempts[ip] += 1

    return ip_requests, endpoint_access, failed_login_attempts

def analyze_log_file(log_file_path, failed_login_threshold=10):
    """
    Perform comprehensive log file analysis.
    
    Args:
        log_file_path (str): Path to the log file
        failed_login_threshold (int): Threshold for suspicious login attempts
    """
    # Parse log file
    ip_requests, endpoint_access, failed_login_attempts = parse_log_file(log_file_path)

    # Print results to terminal
    print("IP Address       Request Count")
    sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint: ")
    most_accessed_endpoint = max(endpoint_access, key=endpoint_access.get)
    print(f"{most_accessed_endpoint} (Accessed {endpoint_access[most_accessed_endpoint]} times)")

    
    suspicious_ips = {ip: count for ip, count in failed_login_attempts.items() if count > failed_login_threshold}
    if suspicious_ips:
        print("\nSuspicious Activity Detected: ")
        print(f"{'IP Address':<20} {'Failed Login Attempts'}")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("\nNo Suspicious Activity Detected.")

    # Save results to CSV
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        
        # Requests per IP section
        csv_writer.writerow(["Requests per IP"])
        csv_writer.writerow(["IP Address", "Request Count"])
        csv_writer.writerows(sorted_ip_requests)
        
        # Most Accessed Endpoint section
        csv_writer.writerow([])  # Empty row for separation
        csv_writer.writerow(["Most Accessed Endpoint"])
        csv_writer.writerow(["Endpoint", "Access Count"])
        csv_writer.writerow([most_accessed_endpoint, endpoint_access[most_accessed_endpoint]])
        
        # Suspicious Activity section
        csv_writer.writerow([])  # Empty row for separation
        csv_writer.writerow(["Suspicious Activity"])
        csv_writer.writerow(["IP Address", "Failed Login Count"])
        csv_writer.writerows(suspicious_ips.items())

def main():
    log_file_path = 'sample.log'
    analyze_log_file(log_file_path)

if __name__ == "__main__":
    main()
