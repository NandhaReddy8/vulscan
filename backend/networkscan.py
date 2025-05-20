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
            "total_ports": 0,
            "open_ports": 0,
            "scan_timestamp": datetime.datetime.now().isoformat()
        },
        "ports": [],
        "host_info": {
            "hostname": "Unknown"
        },
        "scan_time": "0s"
    }
    
    try:
        # Extract hostname
        hostname_match = re.search(r"Nmap scan report for (.*?)\s*\n", output)
        if hostname_match:
            results["host_info"]["hostname"] = hostname_match.group(1)
            
        # Extract scan time
        time_match = re.search(r"scanned in ([\d.]+) seconds", output)
        if time_match:
            results["scan_time"] = f"{time_match.group(1)}s"
            
        # Extract port information
        port_section = False
        for line in output.split('\n'):
            if "PORT" in line and "STATE" in line and "SERVICE" in line:
                port_section = True
                continue
                
            if port_section and line.strip():
                if "Nmap done" in line:
                    break
                    
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0].split('/')
                    if len(port_proto) == 2:
                        port, protocol = port_proto
                        state = parts[1]
                        service = parts[2] if len(parts) > 2 else "unknown"
                        
                        results["ports"].append({
                            "port": port,
                            "protocol": protocol,
                            "state": state,
                            "service": service
                        })
                        
                        if state == "open":
                            results["summary"]["open_ports"] += 1
                            
        results["summary"]["total_ports"] = len(results["ports"])
        logger.debug(f"Parsed {results['summary']['total_ports']} ports, {results['summary']['open_ports']} open")
        
    except Exception as e:
        logger.error(f"Error parsing Nmap output: {str(e)}")
        raise
        
    return results

def run_nmap_scan(ip: str) -> Tuple[bool, str, Optional[dict]]:
    """Run Nmap scan and return (success, output, results)."""
    logger.debug(f"Starting Nmap scan for {ip}")
    
    try:
        nmap_path = get_nmap_path()
        cmd = [
            nmap_path,
            "-sS",  # TCP SYN scan
            "-T4",  # Timing template
            "-F",   # Fast scan
            "--max-retries", "1",
            "--host-timeout", "30s",
            ip
        ]
        
        logger.debug(f"Running Nmap command: {' '.join(cmd)}")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate(timeout=35)
        
        if process.returncode != 0:
            logger.error(f"Nmap scan failed: {stderr}")
            return False, stderr, None
            
        logger.debug("Nmap scan completed successfully")
        results = parse_nmap_output(stdout)
        return True, stdout, results
        
    except subprocess.TimeoutExpired:
        logger.error("Nmap scan timed out")
        return False, "Scan timed out", None
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