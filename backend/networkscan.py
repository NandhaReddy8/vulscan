import subprocess
import sys
import datetime
import ipaddress
import os
import platform
import json
import hashlib
import uuid
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Optional, Tuple, Any, List
from database import (
    create_scan_record,
    update_scan_status,
    get_scan_by_id,
    get_active_scans,
    get_recent_scans
)
import logging
import re
import time
from datetime import timedelta
from psycopg2.extras import DictCursor

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('network_scan.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# Global thread pool for running scans
scan_executor = ThreadPoolExecutor(max_workers=5)  # Limit concurrent scans
active_scans: Dict[str, Dict] = {}  # Track active scans for cancellation
scan_results_cache: Dict[str, Dict] = {}  # Cache scan results to prevent duplicate saves
scan_lock = threading.Lock()  # Lock for thread-safe operations
request_cache = {}  # Cache to track recent requests
request_lock = threading.Lock()  # Lock for request cache operations

def generate_scan_id(ip_address: str, requester_ip: str) -> str:
    """Generate a unique scan ID using UUID."""
    return str(uuid.uuid4())

def is_public_ip(ip: str) -> bool:
    """Check if the given IP is a valid public IP address."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_reserved
    except ValueError:
        return False

def get_nmap_path() -> str:
    """Find Nmap executable path."""
    possible_paths = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        "/usr/bin/nmap",
        "/usr/local/bin/nmap"
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            logger.info(f"Found Nmap at path: {path}")
            return path
            
    raise FileNotFoundError("Nmap executable not found in common locations")

def parse_nmap_output(output: str) -> dict:
    """Parse Nmap scan output into structured format."""
    logger.debug("Parsing Nmap output")
    
    # Initialize results structure
    results = {
        "summary": {
            "total_hosts": 0,
            "up_hosts": 0,
            "scan_timestamp": datetime.datetime.now().isoformat()
        },
        "hosts": [],
        "scan_time": "0s"
    }
    
    try:
        current_host = None
        current_port = None
        in_script_output = False
        
        # Extract scan time
        time_match = re.search(r"scanned in ([\d.]+) seconds", output)
        if time_match:
            results["scan_time"] = f"{time_match.group(1)}s"
            
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            # New host found
            host_match = re.search(r"Nmap scan report for (.*?)\s*$", line)
            if host_match:
                if current_host:
                    results["hosts"].append(current_host)
                current_host = {
                    "hostname": host_match.group(1),
                    "ip": None,
                    "status": "down",
                    "os_info": {},
                    "ports": [],
                    "filtered_ports": 0
                }
                results["summary"]["total_hosts"] += 1
                continue
                
            # IP address
            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            if ip_match and current_host:
                current_host["ip"] = ip_match.group(1)
                
            # Host status
            if "Host is up" in line and current_host:
                current_host["status"] = "up"
                results["summary"]["up_hosts"] += 1
                # Extract latency if available
                latency_match = re.search(r"\(([\d.]+)s latency\)", line)
                if latency_match:
                    current_host["latency"] = latency_match.group(1)
                    
            # Filtered ports
            filtered_match = re.search(r"Not shown: (\d+) filtered tcp ports", line)
            if filtered_match and current_host:
                current_host["filtered_ports"] = int(filtered_match.group(1))
                
            # Port information
            port_match = re.match(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(.*?)(?:\s+(.*))?$", line)
            if port_match and current_host:
                port, protocol, state, service, version = port_match.groups()
                current_port = {
                    "port": port,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "version": version.strip() if version else None,
                    "scripts": {}
                }
                current_host["ports"].append(current_port)
                in_script_output = True
                continue
                
            # Script output
            if in_script_output and current_port and line.startswith("|"):
                script_line = line[1:].strip()  # Remove the leading |
                if ":" in script_line:
                    script_name, script_output = script_line.split(":", 1)
                    script_name = script_name.strip()
                    script_output = script_output.strip()
                    
                    # Handle multi-line script output
                    if script_name in current_port["scripts"]:
                        current_port["scripts"][script_name] += "\n" + script_output
                    else:
                        current_port["scripts"][script_name] = script_output
                        
        # Add the last host
        if current_host:
            results["hosts"].append(current_host)
            
        logger.debug(f"Parsed {results['summary']['total_hosts']} hosts, {results['summary']['up_hosts']} up")
        
        # Log the parsed results for debugging
        logger.debug("Parsed results:")
        logger.debug(json.dumps(results, indent=2))
        
    except Exception as e:
        logger.error(f"Error parsing Nmap output: {str(e)}")
        logger.error("Raw output that caused the error:")
        logger.error(output)
        raise
        
    return results

def run_nmap_scan(ip: str) -> Tuple[bool, str, Optional[dict]]:
    """Run Nmap scan and return (success, output, results)."""
    logger.debug(f"Starting Nmap scan for {ip}")
    
    try:
        nmap_path = get_nmap_path()
        # Modified scan parameters for better results:
        # -T3: Normal timing (less aggressive than T4)
        # -sV: Version detection
        # -sS: TCP SYN scan
        # -O: OS detection
        # -Pn: Skip host discovery (treat all hosts as online)
        # --min-rate 100: Minimum packet rate
        # --max-retries 2: Fewer retries but still reliable
        cmd = [
            nmap_path,
            "-T3",           # Normal timing
            "-sV",           # Version detection
            "-sS",           # TCP SYN scan
            "-O",            # OS detection
            "-Pn",           # Skip host discovery
            "--min-rate", "100",
            "--max-retries", "2",
            "--script", "default",
            "--script-timeout", "30s",
            ip
        ]
        
        logger.debug(f"Running Nmap command: {' '.join(cmd)}")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate(timeout=180)  # Increased timeout to 3 minutes
        
        if process.returncode != 0:
            logger.error(f"Nmap scan failed with return code {process.returncode}: {stderr}")
            return False, stderr, None
            
        # Log the raw output for debugging
        logger.debug("Raw Nmap output:")
        logger.debug(stdout)
            
        logger.debug("Nmap scan completed successfully")
        results = parse_nmap_output(stdout)
        
        # Log the parsed results for debugging
        logger.debug("Parsed scan results:")
        logger.debug(json.dumps(results, indent=2))
        
        return True, stdout, results
        
    except subprocess.TimeoutExpired:
        logger.error("Nmap scan timed out after 180 seconds")
        return False, "Scan timed out after 180 seconds", None
    except Exception as e:
        logger.error(f"Error running Nmap scan: {str(e)}")
        return False, str(e), None

def run_scan_task(scan_id: str, ip: str, requester_ip: str):
    """Run the actual scan task with proper sequencing."""
    logger.info(f"Starting scan task for scan_id: {scan_id}, ip: {ip}")
    
    try:
        # Add to active scans
        with scan_lock:
            active_scans[scan_id] = {
                "ip": ip,
                "start_time": datetime.datetime.now(),
                "status": "running"
            }
            
        # Update status to running
        if not update_scan_status(scan_id, "running"):
            logger.error(f"Failed to update scan status to running for {scan_id}")
            return
            
        # Run the scan
        success, output, results = run_nmap_scan(ip)
        
        if not success:
            logger.error(f"Scan failed for {scan_id}: {output}")
            update_scan_status(scan_id, "failed", error=output)
            return
            
        # Save results and update status to completed in one transaction
        if not update_scan_status(scan_id, "completed", results=results):
            logger.error(f"Failed to save scan results for {scan_id}")
            update_scan_status(scan_id, "failed", error="Failed to save scan results")
            return
            
        logger.info(f"Scan {scan_id} completed and results saved successfully")
        
    except Exception as e:
        logger.error(f"Error in scan task for {scan_id}: {str(e)}")
        update_scan_status(scan_id, "failed", error=str(e))
        
    finally:
        # Only cleanup after results are saved
        with scan_lock:
            if scan_id in active_scans:
                del active_scans[scan_id]
                logger.info(f"Cleaned up scan resources for scan_id: {scan_id}")

def start_network_scan(ip: str, requester_ip: str) -> Tuple[bool, str, Optional[str]]:
    """Start a new network scan with proper request deduplication."""
    logger.debug(f"Starting network scan for IP: {ip} from {requester_ip}")
    
    # Check for duplicate requests
    with request_lock:
        cache_key = f"{ip}:{requester_ip}"
        current_time = time.time()
        
        if cache_key in request_cache:
            last_request_time = request_cache[cache_key]
            if current_time - last_request_time < 5:  # 5 second cooldown
                logger.warning(f"Duplicate scan request for {ip} from {requester_ip}")
                return False, "Please wait before starting another scan", None
                
        request_cache[cache_key] = current_time
        
    try:
        # Check for existing active scans
        active = get_active_scans(ip, requester_ip)
        if active:
            logger.warning(f"Found active scan for {ip} from {requester_ip}")
            return False, "A scan is already in progress for this IP", None
            
        # Generate new scan ID
        scan_id = str(uuid.uuid4())
        logger.debug(f"Generated new scan ID: {scan_id}")
        
        # Create initial scan record
        if not create_scan_record(scan_id, ip, requester_ip):
            return False, "Failed to create scan record", None
            
        # Start scan task in background
        thread = threading.Thread(
            target=run_scan_task,
            args=(scan_id, ip, requester_ip),
            daemon=True
        )
        thread.start()
        
        return True, "Scan started successfully", scan_id
        
    except Exception as e:
        logger.error(f"Error starting network scan: {str(e)}")
        return False, str(e), None

def stop_network_scan(scan_id: str, requester_ip: str) -> Tuple[bool, str]:
    """Stop an active network scan."""
    logger.info(f"Attempting to stop scan {scan_id} from {requester_ip}")
    
    try:
        # Get scan details
        scan = get_scan_by_id(scan_id, requester_ip)
        if not scan:
            return False, "Scan not found"
            
        if scan['scan_status'] not in ['queued', 'running']:
            return False, f"Scan is already {scan['scan_status']}"
            
        # Update status to stopped
        if not update_scan_status(scan_id, "stopped", error="Scan stopped by user"):
            return False, "Failed to update scan status"
            
        # Remove from active scans
        with scan_lock:
            if scan_id in active_scans:
                del active_scans[scan_id]
                
        return True, "Scan stopped successfully"
        
    except Exception as e:
        logger.error(f"Error stopping scan: {str(e)}")
        return False, str(e)

def get_scan_status(scan_id: str, requester_ip: str) -> Tuple[bool, dict]:
    """Get current status of a scan."""
    try:
        scan = get_scan_by_id(scan_id, requester_ip)
        if not scan:
            return False, {"error": "Scan not found"}
            
        return True, {
            "scan_status": scan['scan_status'],
            "scan_results": scan['scan_results'],
            "error_message": scan['error_message'],
            "created_at": scan['created_at'].isoformat(),
            "updated_at": scan['updated_at'].isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting scan status: {str(e)}")
        return False, {"error": str(e)}

def get_recent_scans(ip_address: str, requester_ip: str, minutes: int = 5) -> List[Dict]:
    """Get recent scans for an IP address from a specific requester."""
    try:
        with DatabaseHandler() as db:
            query = """
                SELECT * FROM network_scans 
                WHERE ip_address = %s 
                AND requester_ip = %s 
                AND scan_timestamp > NOW() - INTERVAL %s MINUTE
                ORDER BY scan_timestamp DESC
            """
            db.cursor.execute(query, (ip_address, requester_ip, minutes))
            columns = [desc[0] for desc in db.cursor.description]
            return [dict(zip(columns, row)) for row in db.cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error getting recent scans: {str(e)}")
        return []

def get_active_scans(ip_address: str, requester_ip: str, minutes: int = 5) -> List[Dict]:
    """Get active scans for an IP address from a specific requester."""
    try:
        with DatabaseHandler() as db:
            query = """
                SELECT * FROM network_scans 
                WHERE ip_address = %s 
                AND requester_ip = %s 
                AND created_at > NOW() - INTERVAL %s MINUTE
                AND scan_status IN ('queued', 'running')
                ORDER BY created_at DESC
            """
            db.cursor.execute(query, (ip_address, requester_ip, minutes))
            columns = [desc[0] for desc in db.cursor.description]
            return [dict(zip(columns, row)) for row in db.cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error getting active scans: {str(e)}")
        return []

# Example usage
if __name__ == "__main__":
    async def test_scan():
        test_ip = "8.8.8.8"
        print("\n=== Testing Network Scanner ===\n")
        success, message, scan_id = await start_network_scan(test_ip, "127.0.0.1")
        print(f"\nScan started: {message}")
        print(f"Scan ID: {scan_id}")
        
        if success and scan_id:
            # Wait a bit for results
            await asyncio.sleep(5)
            results = get_scan_status(scan_id, "127.0.0.1")
            print("\nScan Results:")
            print(json.dumps(results, indent=2))
    
    asyncio.run(test_scan())