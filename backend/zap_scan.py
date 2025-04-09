import time
import json
import requests
import os
import csv
from urllib.parse import urlparse, urlunparse
from zapv2 import ZAPv2
from collections import defaultdict
from config import ZAP_URL, ZAP_API_KEY
from urllib.parse import urlparse
import socket
import base64
import re
import logging
import pdfkit

logger = logging.getLogger(__name__)

# Initialize ZAP API
zap = ZAPv2(proxies={"http": ZAP_URL, "https": ZAP_URL}, apikey=ZAP_API_KEY)
print(ZAP_URL)

def check_zap_running():
    """Check if ZAP is running before starting a scan"""
    try:
        response = requests.get(f"{ZAP_URL}")
        return response.status_code == 200
    except requests.exceptions.ConnectionError:
        return False

def is_valid_url(url):
    """Validate if URL is accessible"""
    try:
        parsed = urlparse(url)
        if not all([parsed.scheme, parsed.netloc]):
            return False, "Invalid URL structure"
            
        # Try to resolve the domain
        try:
            socket.gethostbyname(parsed.netloc)
        except socket.gaierror:
            return False, "Unable to resolve domain name"
            
        return True, None
    except Exception as e:
        return False, str(e)

def scan_target(target_url, socketio, scan_id, active_scans):
    session_id = None  # Initialize session_id to avoid referencing before assignment
    try:
        # Clear session data before starting the scan
        clear_session()

        session_id = active_scans.get(scan_id)
        if not session_id:
            raise Exception("No session ID found for scan")

        # Enhanced URL validation
        is_valid, error_msg = is_valid_url(target_url)
        if not is_valid:
            raise ValueError(f"Invalid URL: {error_msg}")

        # Test ZAP connection to URL
        try:
            print(f"[*] Testing connection to: {target_url}")
            zap.urlopen(target_url)
            print("[+] Successfully connected to target")
        except Exception as e:
            print(f"[ERROR] Failed to connect: {str(e)}")
            raise ValueError(f"Cannot reach {target_url}. Please verify the URL is accessible.")

        # Continue with scan only if validation passes
        print(f"[+] Starting scan for: {target_url}")

        # Spider Scan Phase
        socketio.emit('scan_progress', {
            'message': 'Starting Spider Scan...',
            'progress': 0,
            'phase': 'Spider Scan'
        }, room=session_id)

        try:
            spider_scan_id = zap.spider.scan(target_url)
            if not spider_scan_id:
                raise Exception("Failed to initiate spider scan")
            print(f"[+] Spider scan initiated: {spider_scan_id}")
        except Exception as e:
            print(f"[ERROR] Spider scan failed: {str(e)}")
            raise Exception(f"Failed to start scan: {str(e)}")

        time.sleep(2)

        while int(zap.spider.status(spider_scan_id)) < 100:
            progress = int(zap.spider.status(spider_scan_id))
            socketio.emit('scan_progress', {
                'message': f'Discovering site structure...',
                'progress': progress,
                'phase': 'Spider Scan'
            }, room=session_id)
            time.sleep(2)

        # Passive Scan Phase
        socketio.emit('scan_progress', {
            'message': 'Starting Passive Scan...',
            'progress': 95,
            'phase': 'Passive Scan'
        }, room=session_id)

        zap.pscan.enable_all_scanners()
        time.sleep(2)

        while int(zap.pscan.records_to_scan) > 0:
            records_left = int(zap.pscan.records_to_scan)
            socketio.emit('scan_progress', {
                'message': f'Analyzing {records_left} records...',
                'progress': 99,
                'phase': 'Passive Scan'
            }, room=session_id)
            time.sleep(2)

        # Generate HTML Report
        socketio.emit('scan_progress', {
            'message': 'Generating HTML Report...',
            'progress': 99,
            'phase': 'Report Generation'
        }, room=session_id)

        try:
            html_report = zap.core.htmlreport()
            safe_filename = target_url.replace("://", "_").replace("/", "_")
            output_dir = "./zap_reports"
            os.makedirs(output_dir, exist_ok=True)
            html_file = f"{output_dir}/{safe_filename}.html"

            # Save the customized HTML report
            with open(html_file, "w", encoding="utf-8") as f:
                f.write(customize_report(html_report))

            print(f"[+] HTML report saved to {html_file}")

            # Convert HTML to PDF
            pdf_file = f"{output_dir}/{safe_filename}.pdf"
            generate_pdf_from_html(html_file, pdf_file)

        except Exception as e:
            print(f"[ERROR] Failed to generate HTML or PDF report: {str(e)}")

        # Final completion
        socketio.emit('scan_progress', {
            'message': 'Scan Complete! Processing results...',
            'progress': 100,
            'phase': 'Completed'
        }, room=session_id)

        # Process and emit results
        alerts = zap.core.alerts(baseurl=target_url)
        results = process_scan_results(alerts)

        # Save results
        save_scan_results(target_url, results)
        
        # Emit completion event
        socketio.emit("scan_completed", {
            "message": "Scan Completed!",
            "result": results,
            "html_report": html_file,  # Include HTML report path in the response
            "pdf_report": pdf_file     # Include PDF report path in the response
        }, room=session_id)

        return results

    except ValueError as ve:
        error_msg = str(ve)
        print(f"[ERROR] Validation failed: {error_msg}")
        if session_id:
            socketio.emit('scan_error', {
                'error': error_msg,
                'type': 'validation_error'
            }, room=session_id)
    except Exception as e:
        error_msg = str(e)
        print(f"[ERROR] Scan failed: {error_msg}")
        if session_id:
            socketio.emit('scan_error', {
                'error': error_msg,
                'type': 'scan_error'
            }, room=session_id)
    finally:
        if session_id:
            active_scans.pop(scan_id, None)

def scan_target_old(target_url, socketio):
    """Performs a ZAP Spider and Passive Scan on the given target URL with real-time progress updates"""
    if not check_zap_running():
        print("[ERROR] ZAP Proxy is not running! Start ZAP before running scans.")
        socketio.emit("scan_error", {"error": "ZAP Proxy is not running"})
        return {"error": "ZAP Proxy is not running"}

    try:
        print(f"[*] Starting ZAP Spider scan on {target_url}")
        socketio.emit("scan_progress", {"message": "Starting Spider Scan...", "progress": 0})

        scan_id = zap.spider.scan(target_url)
        time.sleep(2)

        while int(zap.spider.status(scan_id)) < 100:
            progress = int(zap.spider.status(scan_id))
            print(f"[*] Spider progress: {progress}%")
            socketio.emit("scan_progress", {"message": f"[{progress}%] Spidering in progress...", "progress": progress})
            time.sleep(5)

        print("[*] Spidering completed! Starting Passive Scan...")
        socketio.emit("scan_progress", {"message": "Spider completed. Starting Passive Scan...", "progress": 100})

        zap.pscan.enable_all_scanners()
        time.sleep(2)

        while int(zap.pscan.records_to_scan) > 0:
            records_left = int(zap.pscan.records_to_scan)
            print(f"[*] Passive Scan Progress: {records_left}")
            socketio.emit("scan_progress", {"message": "Passive Scan in progress...", "progress": 100})
            time.sleep(5)

        print("[*] Passive Scan completed!")
        socketio.emit("scan_progress", {"message": "Passive Scan completed!", "progress": 100})

        # Fetch alerts
        alerts = zap.core.alerts(baseurl=target_url)
        vulnerabilities_by_type = defaultdict(lambda: {"risk": None, "description": None, "count": 0, "affected_urls": []})

        for alert in alerts:
            description = alert.get("description", "No description available")
            risk = alert.get("risk", "Info").capitalize()
            url = alert.get("url", "No URL")

            vulnerabilities_by_type[description]["risk"] = risk
            vulnerabilities_by_type[description]["description"] = description
            vulnerabilities_by_type[description]["count"] += 1
            if url not in vulnerabilities_by_type[description]["affected_urls"]:
                vulnerabilities_by_type[description]["affected_urls"].append(url)

        summary = defaultdict(int)
        for vulnerability in vulnerabilities_by_type.values():
            summary[vulnerability["risk"]] += 1

        final_results = {
            "summary": dict(summary),
            "vulnerabilities_by_type": [
                {
                    "risk": vuln["risk"],
                    "description": vuln["description"],
                    "count": len(vuln["affected_urls"]),
                    "affected_urls": vuln["affected_urls"][:3] + (
                        ["and {} other sites".format(len(vuln["affected_urls"]) - 3)]
                        if len(vuln["affected_urls"]) > 3
                        else []
                    )
                } for vuln in vulnerabilities_by_type.values()
            ]
        }

        # Save results to JSON file
        safe_filename = target_url.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "").replace("?", "")
        output_dir = "./zap_results"
        os.makedirs(output_dir, exist_ok=True)  # Ensure directory exists
        output_file = f"{output_dir}/{safe_filename}.json"

        with open(output_file, "w") as file:
            json.dump(final_results, file, indent=4)

        print(f"\n[*] Vulnerability scan completed! Results saved to '{output_file}'.")
        socketio.emit("scan_completed", {"message": "Scan Completed!", "result": final_results})

        return final_results

    except Exception as e:
        print(f"[ERROR] An issue occurred: {e}")
        socketio.emit("scan_error", {"error": str(e)})
        return {"error": str(e)}

def process_scan_results(alerts):
    """Process ZAP alerts into a structured format with detailed vulnerability information"""
    vulnerabilities_by_type = defaultdict(lambda: {
        "risk": None,
        "alert_type": None,  # Added alert_type field
        "alert_tags": None,
        "parameter": None,
        "evidence": None,
        "description": None,
        "solution": None,
        "count": 0,
        "affected_urls": []
    })

    for alert in alerts:
        description = alert.get("description", "No description available")
        risk = alert.get("risk", "Info").capitalize()
        url = alert.get("url", "No URL")
        
        # Get alert name/type and instance count
        alert_name = alert.get("name", "Unknown Alert")
        instance_count = alert.get("count", 1)
        alert_type = f"{alert_name} ({instance_count})"

        # Extract and format CWE and WASC IDs safely
        cwe_id = alert.get("cweid", "Unknown")
        wasc_id = alert.get("wascid", "Unknown")
        
        # Format alert tags safely
        if wasc_id != "Unknown" and wasc_id.isdigit():
            alert_tags = f"CWE-{cwe_id}, OWASP 2021 A{int(wasc_id):02d}"
        else:
            alert_tags = f"CWE-{cwe_id}"

        vuln_data = vulnerabilities_by_type[description]
        vuln_data.update({
            "risk": risk,
            "alert_type": alert_type,  # Added alert type
            "alert_tags": alert_tags,
            "parameter": alert.get("param", "Not specified"),
            "evidence": alert.get("evidence", "Not available"),
            "description": description,
            "solution": alert.get("solution", "No solution provided"),
            "count": vuln_data["count"] + 1
        })

        if url not in vuln_data["affected_urls"]:
            vuln_data["affected_urls"].append(url)

    # Format final results
    return {
        "summary": dict(defaultdict(int, {
            risk: sum(1 for v in vulnerabilities_by_type.values() if v["risk"] == risk)
            for risk in set(v["risk"] for v in vulnerabilities_by_type.values())
        })),
        "vulnerabilities_by_type": [
            {
                "risk": vuln["risk"],
                "alert_type": vuln["alert_type"],  # Added to output
                "alert_tags": vuln["alert_tags"],
                "parameter": vuln["parameter"],
                "evidence": vuln["evidence"],
                "description": vuln["description"],
                "solution": vuln["solution"],
                "count": len(vuln["affected_urls"]),
                "affected_urls": vuln["affected_urls"][:3] + (
                    ["...and {} more".format(len(vuln["affected_urls"]) - 3)]
                    if len(vuln["affected_urls"]) > 3
                    else []
                )
            } for vuln in vulnerabilities_by_type.values()
        ]
    }

def save_scan_results(target_url, results):
    """Save scan results to JSON file"""
    safe_filename = target_url.replace("://", "_").replace("/", "_")
    output_dir = "./zap_results"
    os.makedirs(output_dir, exist_ok=True)
    
    output_file = f"{output_dir}/{safe_filename}.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)
    
    print(f"[*] Results saved to {output_file}")

def clear_session():
    """Clear current session data in ZAP"""
    try:
        # Generate a unique session name based on timestamp
        session_name = f"session_{int(time.time())}"
        
        # Create a new session and ensure no merging of previous data
        zap.core.new_session(name=session_name, overwrite=True)
        
        # Clear all alerts
        zap.core.delete_all_alerts()
        logger.info(f"Cleared previous session data and created a new session: {session_name}")
    except Exception as e:
        logger.error(f"Failed to clear session: {str(e)}")
        raise

def normalize_url(url):
    """Normalize the URL to ensure consistency"""
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"  # Default to http if no scheme is provided
    netloc = parsed.netloc.lower()  # Ensure the domain is lowercase
    path = parsed.path.rstrip("/")  # Remove trailing slashes
    return urlunparse((scheme, netloc, path, "", "", ""))

def customize_report(html_content):
    """Customize the ZAP HTML report to remove ZAP branding and add VirtuesTech branding."""
    try:
        # Read VirtuesTech logo
        logo_path = os.path.join(os.path.dirname(__file__), 'virtuestech_logo.png')
        if not os.path.exists(logo_path):
            logger.error(f"Logo not found at: {logo_path}")
            return html_content

        # Convert logo to base64
        with open(logo_path, 'rb') as f:
            logo_base64 = base64.b64encode(f.read()).decode('utf-8')

        # Add CSS for styling - adjusted margins and padding in report-header
        css_styles = '''
        <style>
            body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 0;
            background-color: #f9f9f9;
            }
            .report-header {
            text-align: center;
            background-color: #f9f9f9;
            color: black;
            padding: 10px 0;  /* Reduced padding from 20px to 10px */
            margin-bottom: 20px;  /* Reduced margin from 30px to 20px */
            border-bottom: 2px solid #004080;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 5px;  /* Added small gap between elements */
            }
            .report-header img {
            width: 300px;
            height: auto;
            margin: 0 auto;
            display: block;
            margin-bottom: 5px;  /* Added small bottom margin to logo */
            }
            .report-header h1 {
            margin: 0;  /* Removed all margins */
            font-size: 28px;
            color: black;
            }
            /* Rest of the CSS remains the same */
            .report-content {
            padding: 20px;
            background: white;
            margin: 20px auto;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            max-width: 900px;
            }
            .footer {
            text-align: center;
            margin-top: 30px;
            font-size: 12px;
            color: #666;
            }
            .footer-logo {
            width: 150px;  /* Increased from 80px to 150px (half of header logo size) */
            height: auto;
            margin-top: 10px;
            }
            table {
            width: 80%;
            margin: 20px auto;
            border-collapse: collapse;
            font-size: 14px;
            border: 1px solid #ddd;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            }
            table th, table td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
            vertical-align: top;
            }
            table th {
            background-color: #004080;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            }
            table tr:nth-child(even) {
            background-color: #f2f2f2;
            }
            table tr:hover {
            background-color: #e6f7ff;
            }
            .table-title {
            font-size: 18px;
            font-weight: bold;
            margin: 10px auto;
            color: #004080;
            text-transform: uppercase;
            text-align: center;
            }
            .risk-high {
            color: #d9534f;
            font-weight: bold;
            }
            .risk-medium {
            color: #f0ad4e;
            font-weight: bold;
            }
            .risk-low {
            color: #5bc0de;
            font-weight: bold;
            }
            .risk-info {
            color: #5cb85c;
            font-weight: bold;
            }
        </style>
        '''

        # Rest of the function remains the same
        new_header = f'''
        <div class="report-header">
            <img src="data:image/png;base64,{logo_base64}" alt="VirtuesTech Logo" />
            <h1>VirtuesTech Security Scan Report</h1>
        </div>
        '''

        footer = f'''
        <div class="footer">
            <p>Report generated by VirtuesTech Security Scanner</p>
            <img src="data:image/png;base64,{logo_base64}" class="footer-logo" alt="VirtuesTech Logo" />
        </div>
        '''

        # Add CSS to the head section
        html_content = re.sub(
            r'</head>',
            f'{css_styles}</head>',
            html_content
        )

        # Replace existing header with the new header
        html_content = re.sub(
            r'<h1>.*?</h1>\s*<p\s*/>',
            new_header,
            html_content,
            flags=re.DOTALL
        )

        # Add footer before the closing body tag
        html_content = re.sub(
            r'</body>',
            f'{footer}</body>',
            html_content
        )

        # Remove ZAP-specific content
        patterns_to_remove = [
            r'<h3>\s*ZAP Version:.*?</h3>',
            r'<h4>\s*ZAP by.*?</h4>',
            r'<title>ZAP.*?</title>'
        ]
        for pattern in patterns_to_remove:
            html_content = re.sub(pattern, '', html_content, flags=re.DOTALL)

        # Add a new title to the report
        html_content = re.sub(
            r'<head>',
            '<head>\n<title>VirtuesTech Security Scan Report</title>',
            html_content
        )

        return html_content

    except Exception as e:
        logger.error(f"Failed to customize report: {str(e)}")
        return html_content

import pdfkit
import os

# Function to configure wkhtmltopdf path based on the operating system
def get_wkhtmltopdf_path():
    """Determine the wkhtmltopdf binary path based on the operating system."""
    if os.name == 'nt':  # Windows
        possible_paths = [
            r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe',
            r'C:\Program Files (x86)\wkhtmltopdf\bin\wkhtmltopdf.exe',
            r'C:\wkhtmltopdf\bin\wkhtmltopdf.exe'
        ]
    else:  # Linux/Unix-based systems
        possible_paths = [
            '/usr/local/bin/wkhtmltopdf',
            '/usr/bin/wkhtmltopdf',
            '/bin/wkhtmltopdf'
        ]

    for path in possible_paths:
        if os.path.exists(path):
            return path

    raise Exception("wkhtmltopdf not found. Please install it from https://wkhtmltopdf.org/downloads.html")

# Configure wkhtmltopdf for pdfkit
try:
    wkhtmltopdf_path = get_wkhtmltopdf_path()
    pdfkit_config = pdfkit.configuration(wkhtmltopdf=wkhtmltopdf_path)
    print(f"[+] wkhtmltopdf found at: {wkhtmltopdf_path}")
except Exception as e:
    print(f"[ERROR] {str(e)}")
    raise

# Function to generate PDF from HTML
def generate_pdf_from_html(html_file, pdf_file):
    """Generate a PDF from an HTML file using pdfkit."""
    try:
        pdfkit.from_file(html_file, pdf_file, configuration=pdfkit_config)
        print(f"[+] PDF report saved to {pdf_file}")
    except Exception as e:
        print(f"[ERROR] Failed to generate PDF: {str(e)}")
        raise
