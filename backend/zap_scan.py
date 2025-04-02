import time
import json
import requests
import os
import csv
from zapv2 import ZAPv2
from collections import defaultdict
from config import ZAP_URL, ZAP_API_KEY
from urllib.parse import urlparse
import socket

# Initialize ZAP API
zap = ZAPv2(proxies={"http": ZAP_URL, "https": ZAP_URL}, apikey=ZAP_API_KEY)

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
    try:
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
            "result": results
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
