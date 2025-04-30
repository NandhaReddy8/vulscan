import csv
import os

# Define CSV file paths
SCAN_REQUESTS_FILE = "scan_requests.csv"
REPORT_REQUESTS_FILE = "report_requests.csv"

# Ensure the CSV files exist
def initialize_csv(file_path, headers):
    """Create a CSV file with headers if it doesn't exist."""
    if not os.path.exists(file_path):
        with open(file_path, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(headers)  # Write column headers

# Initialize CSV files
initialize_csv(SCAN_REQUESTS_FILE, ["url", "ip_address", "timestamp"])  # Changed headers to match
initialize_csv(REPORT_REQUESTS_FILE, ["Name", "Email", "Phone", "Target URL", "Timestamp"])

# Function to save a scan request
def save_scan_request(url, ip_address, timestamp):
    """Save scan request with consistent headers"""
    with open(SCAN_REQUESTS_FILE, "a", newline="", encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([url, ip_address, timestamp])

# Function to save a report request
def save_report_request(name, email, Phone, Target_URL, Timestamp):
    with open(REPORT_REQUESTS_FILE, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([name, email, Phone, Target_URL])

# Function to retrieve stored scan requests
def get_scan_requests():
    with open(SCAN_REQUESTS_FILE, "r") as file:
        reader = csv.DictReader(file)
        return list(reader)

# Function to retrieve stored report requests
def get_report_requests():
    with open(REPORT_REQUESTS_FILE, "r") as file:
        reader = csv.DictReader(file)
        return list(reader)

# Function to delete all scan requests