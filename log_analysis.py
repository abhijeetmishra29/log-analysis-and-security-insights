import csv
from collections import defaultdict

# Constants
default_threshold = 1  # Default threshold for suspicious activity

def parse_log_file(file_path):
    ip_requests = defaultdict(int)
    endpoint_counts = defaultdict(int)
    failed_logins = defaultdict(int)

    with open(file_path, 'r') as file:
        for line in file:
            parts = line.split()
            if len(parts) < 9:
                continue  # Skip malformed lines
            
            ip = parts[0]
            request_info = parts[5:7]
            status_code = parts[8]

            print(f"Parsing line: {line.strip()}")
            print(f"IP: {ip}, Status Code: {status_code}")

            endpoint = request_info[1] if len(request_info) > 1 else "Unknown"
            
            # Count IP requests
            ip_requests[ip] += 1

            # Count endpoint accesses
            endpoint_counts[endpoint] += 1

            # Count failed login attempts
            if status_code == "401":  # Failed login attempt
                failed_logins[ip] += 1

    return ip_requests, endpoint_counts, failed_logins

def write_to_csv(ip_requests, most_accessed, suspicious_ips, file_path):
    """Write the results to a CSV file."""
    with open(file_path, mode='w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write IP requests
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])  # Blank line
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])

        # Write suspicious activity
        writer.writerow([])  # Blank line
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

def main(log_file, output_file, threshold=default_threshold):
    # Parse the log file
    ip_requests, endpoint_counts, failed_logins = parse_log_file(log_file)

    # Find the most accessed endpoint
    most_accessed_endpoint = max(endpoint_counts.items(), key=lambda x: x[1])

    # Detect suspicious activity
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}

    # Write results to CSV
    write_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips, output_file)

    # Display results
    print("IP Address           Request Count")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

if __name__ == "__main__":
    log_file_path = "sample.log"
    output_file_path = "log_analysis_results.csv"
    main(log_file_path, output_file_path)
