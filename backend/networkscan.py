import subprocess
import sys
import datetime
import ipaddress
import os
import platform
import json
import hashlib
import uuid
from typing import Dict, Optional, Tuple, Any
from database import DatabaseHandler, save_scan_request, save_network_scan_results, get_network_scan_results
import logging

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG for more detailed logs
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),  # Log to console
        logging.FileHandler('network_scan.log', encoding='utf-8')  # Log to file with UTF-8 encoding
    ]
)
logger = logging.getLogger(__name__)

# Set stdout encoding to UTF-8
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

db = DatabaseHandler()

def generate_scan_id(ip_address: str, requester_ip: str) -> str:
    """Generate a unique, hashed scan ID using the IP address, requester IP, and a random UUID."""
    # Combine inputs with a random UUID to ensure uniqueness
    unique_string = f"{ip_address}:{requester_ip}:{uuid.uuid4()}"
    return hashlib.sha256(unique_string.encode()).hexdigest()

def is_public_ip(ip_str: str) -> bool:
    """Validate if the provided IP is a public IPv4 address."""
    try:
        ip = ipaddress.ip_address(ip_str)
        is_valid = ip.version == 4 and not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast)
        logger.info(f"IP validation for {ip_str}: {'valid' if is_valid else 'invalid'} public IP")
        return is_valid
    except ValueError as e:
        logger.error(f"Invalid IP address format: {ip_str} - {str(e)}")
        return False

def get_nmap_path() -> str:
    """Determine the path to the Nmap executable based on the operating system."""
    if platform.system() == "Windows":
        # Try 32-bit path first
        win_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
        if os.path.exists(win_path):
            logger.info(f"Found Nmap at 32-bit path: {win_path}")
            return win_path
            
        # Try 64-bit path
        win_path_64 = r"C:\Program Files\Nmap\nmap.exe"
        if os.path.exists(win_path_64):
            logger.info(f"Found Nmap at 64-bit path: {win_path_64}")
            return win_path_64
            
        # Fallback to PATH
        logger.warning("Nmap not found in default locations, trying PATH")
        return "nmap"
    else:
        logger.info("Non-Windows system, using PATH for nmap")
        return "nmap"

def parse_nmap_output(output: str) -> Dict[str, Any]:
    """Parse the output from Nmap into a structured JSON format."""
    lines = output.split("\n")
    result = {
        "hostname": None,
        "ip": None,
        "open_ports": [],
        "scan_time": None,
        "os_info": None,
        "services": []
    }

    current_service = None
    for line in lines:
        line = line.strip()
        if "Nmap scan report for" in line:
            # Extract hostname and IP
            parts = line.split("for ")[1].split(" (")
            result["hostname"] = parts[0]
            if len(parts) > 1:
                result["ip"] = parts[1].rstrip(")")
        elif "open" in line and "tcp" in line:
            # Parse open port line
            try:
                port_line = line.split()
                port = int(port_line[0].split("/")[0])
                state = port_line[1]
                service = port_line[2] if len(port_line) > 2 else "unknown"
                version = " ".join(port_line[3:]) if len(port_line) > 3 else None
                
                service_info = {
                    "port": port,
                    "state": state,
                    "service": service,
                    "version": version
                }
                result["services"].append(service_info)
                result["open_ports"].append(port)
            except (IndexError, ValueError) as e:
                logger.warning(f"Failed to parse port line: {line}, error: {e}")
        elif "Scan completed" in line:
            # Extract scan time
            try:
                time_str = line.split("in ")[1].split(" seconds")[0]
                result["scan_time"] = float(time_str)
            except (IndexError, ValueError) as e:
                logger.warning(f"Failed to parse scan time: {line}, error: {e}")
        elif "Service Info:" in line:
            # Extract OS and service information
            try:
                info_parts = line.split("Service Info:")[1].strip()
                result["os_info"] = info_parts
            except (IndexError, ValueError) as e:
                logger.warning(f"Failed to parse service info: {line}, error: {e}")

    # Convert the result to a JSON string and back to ensure consistent format
    try:
        result_json = json.dumps(result)
        return json.loads(result_json)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to serialize scan results: {e}")
        return {
            "error": "Failed to parse scan results",
            "raw_output": output
        }

def run_nmap(ip: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Run Nmap command and return success status, output, and parsed results."""
    nmap_path = get_nmap_path()
    logger.info(f"Using Nmap executable at: {nmap_path}")
    
    # Build command
    cmd = [
        nmap_path,
        "-sV",  # Service/version detection
        "-T4",  # Timing template (4 = aggressive)
        "-F",   # Fast scan (fewer ports)
        ip,
    ]
    
    # Use a simple ASCII message instead of emoji
    logger.info(f"Running Nmap command: {' '.join(cmd)}")
    
    try:
        # Use subprocess.Popen to stream output line by line
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=(platform.system() == "Windows")  # Use shell=True on Windows
        )
        
        # Collect output while logging in real-time
        stdout_lines = []
        stderr_lines = []
        
        # Read stdout
        for line in process.stdout:
            line = line.strip()
            stdout_lines.append(line)
            logger.debug(f"Nmap output: {line}")
            print(f"Nmap: {line}")  # Print to console in real-time
            
        # Read stderr
        for line in process.stderr:
            line = line.strip()
            stderr_lines.append(line)
            logger.warning(f"Nmap stderr: {line}")
            print(f"Nmap error: {line}")  # Print to console in real-time
            
        # Wait for process to complete
        returncode = process.wait()
        stdout = '\n'.join(stdout_lines)
        stderr = '\n'.join(stderr_lines)
        
        if returncode != 0:
            error_msg = f"Nmap scan failed with return code {returncode}: {stderr}"
            logger.error(error_msg)
            print(f"Error: {error_msg}")  # Use ASCII instead of emoji
            return False, error_msg, None
            
        logger.info("Nmap scan completed successfully")
        parsed = parse_nmap_output(stdout)
        return True, stdout, parsed
        
    except subprocess.TimeoutExpired:
        error_msg = "Nmap scan timed out after 5 minutes"
        logger.error(error_msg)
        print(f"Error: {error_msg}")  # Use ASCII instead of emoji
        process.kill()
        return False, error_msg, None
    except Exception as e:
        error_msg = f"Error running Nmap: {str(e)}"
        logger.error(error_msg)
        print(f"Error: {error_msg}")  # Use ASCII instead of emoji
        return False, error_msg, None

def scan_network(ip_address: str, requester_ip: str) -> Tuple[bool, str, Optional[str]]:
    """
    Main function to handle the network scanning workflow.
    """
    logger.info(f"Starting network scan for IP: {ip_address} from requester: {requester_ip}")
    
    if not is_public_ip(ip_address):
        error_msg = f"Invalid or non-public IP address: {ip_address}"
        logger.error(error_msg)
        return False, error_msg, None

    try:
        # Generate a unique scan ID
        scan_id = generate_scan_id(ip_address, requester_ip)
        timestamp = datetime.datetime.now()
        logger.info(f"Generated scan ID: {scan_id}")

        # Save initial scan request and ensure it's committed
        logger.info("Saving initial scan request to database")
        try:
            request_id = save_scan_request(
                url=None,
                ip_address=ip_address,
                timestamp=timestamp,
                scan_id=scan_id,
            )
            if not request_id:
                error_msg = "Failed to save scan request to database"
                logger.error(error_msg)
                return False, error_msg, None
            logger.info(f"Scan request saved with ID: {request_id}")
        except Exception as e:
            error_msg = f"Failed to save scan request: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, None

        # Update status to "running"
        logger.info("Updating scan status to 'running'")
        try:
            save_network_scan_results(
                scan_id=scan_id,
                ip_address=ip_address,
                scan_status="running",
                requester_ip=requester_ip,
                scan_results=None,
                error_message=None
            )
        except Exception as e:
            error_msg = f"Failed to update scan status: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, None

        # Run the scan
        logger.info("Starting Nmap scan")
        success, output, parsed = run_nmap(ip_address)

        if not success:
            logger.error(f"Scan failed: {output}")
            # Update status to "failed" with error
            try:
                save_network_scan_results(
                    scan_id=scan_id,
                    ip_address=ip_address,
                    scan_status="failed",
                    error_message=output,
                    requester_ip=requester_ip,
                    scan_results=None
                )
            except Exception as e:
                logger.error(f"Failed to update scan status to failed: {str(e)}")
            return False, output, scan_id

        logger.info("Scan completed successfully, saving results")
        # Debug log the parsed results
        logger.debug(f"Parsed results type: {type(parsed)}")
        logger.debug(f"Parsed results: {json.dumps(parsed, indent=2)}")

        try:
            # Ensure parsed results are properly formatted
            if parsed is None:
                scan_results = None
            else:
                # Convert to JSON string if it's a dict
                if isinstance(parsed, dict):
                    scan_results = json.dumps(parsed)
                elif isinstance(parsed, str):
                    # If it's already a string, validate it's proper JSON
                    try:
                        # Try to parse and re-stringify to ensure valid JSON
                        scan_results = json.dumps(json.loads(parsed))
                    except json.JSONDecodeError:
                        logger.error("Invalid JSON in parsed results")
                        scan_results = json.dumps({"error": "Invalid scan results format"})
                else:
                    logger.error(f"Unexpected parsed results type: {type(parsed)}")
                    scan_results = json.dumps({"error": "Invalid scan results format"})

            # Debug log the scan results before saving
            logger.debug(f"Scan results type: {type(scan_results)}")
            if scan_results:
                logger.debug(f"Scan results preview: {scan_results[:100]}...")

            save_network_scan_results(
                scan_id=scan_id,
                ip_address=ip_address,
                scan_status="completed",
                scan_results=scan_results,  # Pass as JSON string
                requester_ip=requester_ip,
                error_message=None
            )
        except Exception as e:
            error_msg = f"Failed to save scan results: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, scan_id

        return True, "Scan completed successfully", scan_id

    except Exception as e:
        error_msg = f"Scan error: {str(e)}"
        logger.error(error_msg)
        print(f"Error: {error_msg}")  # Use ASCII instead of emoji
        
        # If we have a scan_id, update its status to failed
        if 'scan_id' in locals():
            try:
                logger.info("Updating scan status to 'failed' due to error")
                save_network_scan_results(
                    scan_id=scan_id,
                    ip_address=ip_address,
                    scan_status="failed",
                    error_message=str(e),
                    requester_ip=requester_ip,
                    scan_results=None
                )
                return False, error_msg, scan_id
            except Exception as db_error:
                logger.error(f"Failed to update scan status: {str(db_error)}")
        return False, error_msg, None

if __name__ == "__main__":
    # Example usage (for testing)
    test_ip = "8.8.8.8"  # Google DNS
    print("\n=== Testing Network Scanner ===\n")
    success, message, scan_id = scan_network(test_ip, "127.0.0.1")
    print(f"\nScan {'succeeded' if success else 'failed'}: {message}")
    print(f"Scan ID: {scan_id}")

    if success and scan_id:
        print("\nRetrieving scan results...")
        results = get_network_scan_results(scan_id, "127.0.0.1")
        print("\nScan Results:")
        print(json.dumps(results, indent=2))