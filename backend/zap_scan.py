import time
import json
import requests
import os
import csv
from zapv2 import ZAPv2
from collections import defaultdict
from config import ZAP_URL, ZAP_API_KEY

# Initialize ZAP API
zap = ZAPv2(proxies={"http": ZAP_URL, "https": ZAP_URL}, apikey=ZAP_API_KEY)

def check_zap_running():
    """Check if ZAP is running before starting a scan"""
    try:
        response = requests.get(f"{ZAP_URL}")
        return response.status_code == 200
    except requests.exceptions.ConnectionError:
        return False

def scan_target(target_url, socketio):
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
            socketio.emit("scan_progress", {"message": "Spidering in progress...", "progress": progress})
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
        socketio.emit("scan_completed", {"message": "Scan Completed!", "file": output_file})

        return final_results

    except Exception as e:
        print(f"[ERROR] An issue occurred: {e}")
        socketio.emit("scan_error", {"error": str(e)})
        return {"error": str(e)}
