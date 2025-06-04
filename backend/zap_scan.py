import time
import json
import requests
import os
from urllib.parse import urlparse, urlunparse
from zapv2 import ZAPv2
from collections import defaultdict
from config import ZAP_URL, ZAP_API_KEY
from urllib.parse import urlparse
import socket
import base64
import re
import logging
from db_handler import DatabaseHandler
db = DatabaseHandler()

logger = logging.getLogger(__name__)


# Initialize ZAP API
zap = ZAPv2(proxies={"http": ZAP_URL, "https": ZAP_URL}, apikey=ZAP_API_KEY)
print(ZAP_URL)

active_scan_contexts = {}

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

def check_target_accessibility(url):
    """Check if target URL is accessible via ZAP"""
    try:
        print(f"[*] Checking accessibility for {url}")
        
        # Configure requests to use ZAP as proxy
        proxies = {
            "http": ZAP_URL,
            "https": ZAP_URL
        }

        # Make request through ZAP proxy
        response = requests.get(
            url,
            proxies=proxies,
            verify=False,
            timeout=10,
            allow_redirects=True
        )
        
        status_code = response.status_code
        print(f"[+] Target URL response status code: {status_code}")
        
        # Accept 2xx status codes as success
        if 200 <= status_code < 300:
            return True, None
        else:
            return False, f"Target returned status code: {status_code}"

    except requests.exceptions.RequestException as e:
        error_msg = f"Connection error: {str(e)}"
        print(f"[-] {error_msg}")
        return False, error_msg
    except Exception as e:
        error_msg = f"Error checking target: {str(e)}"
        print(f"[-] {error_msg}")
        return False, error_msg

def create_scan_context(scan_id, target_url):
    """Create a new ZAP context for this scan"""
    try:
        context_name = f"context_{scan_id}"
        context_id = zap.context.new_context(context_name)
        
        # Include target URL in context
        zap.context.include_in_context(context_name, f".*{target_url}.*")
        
        active_scan_contexts[scan_id] = {
            'context_id': context_id,
            'context_name': context_name,
            'target_url': target_url,
            'start_time': time.time()
        }
        
        print(f"[+] Created new context {context_name} for scan {scan_id}")
        return context_name
    except Exception as e:
        print(f"[ERROR] Failed to create context: {str(e)}")
        raise

def sanitize_url(url):
    """
    Remove leading/trailing whitespace and invisible characters from the URL.
    """
    if not isinstance(url, str):
        return ""
    # Remove leading/trailing whitespace, newlines, tabs, and zero-width spaces
    return url.strip().replace('\u200b', '').replace('\u200c', '').replace('\u200d', '').replace('\ufeff', '')

def scan_target(target_url, socketio, scan_id, active_scans):
    """Perform scan with isolated context"""
    session_id = None
    context_name = None

    # Sanitize the URL before any validation or scan
    target_url = sanitize_url(target_url)

    try:
        session_id = active_scans.get(scan_id)
        if not session_id:
            raise Exception("No session ID found for scan")
            
        # Check if target is accessible
        is_accessible, error = check_target_accessibility(target_url)
        if not is_accessible:
            raise Exception(f"Target URL is not accessible: {error}")

        context_name = create_scan_context(scan_id, target_url)

       
        
        # Spider scan
        print(f"[*] Starting spider scan for context {context_name}")
        spider_scan_id = zap.spider.scan(
            url=target_url,
            contextname=context_name
        )
        
        while int(zap.spider.status(spider_scan_id)) < 85:
            if scan_id not in active_scans:
                print(f"[*] Spider scan stopped by user for {target_url}")
                return
                
            progress = int(zap.spider.status(spider_scan_id))
            socketio.emit('scan_progress', {
                'scan_id': scan_id,
                'message': f'Discovering site structure...',
                'progress': progress,
                'phase': 'Spider Scan'
            }, room=session_id)
            time.sleep(2)

        # Check if scan was stopped
        if scan_id not in active_scans:
            return

        # Passive scan
        print(f"[*] Starting passive scan for context {context_name}")
        zap.pscan.enable_all_scanners()
        
        while int(zap.pscan.records_to_scan) > 0:
            if scan_id not in active_scans:
                print(f"[*] Passive scan stopped by user for {target_url}")
                return
                
            records_left = int(zap.pscan.records_to_scan)
            progress = max(50, min(95, 100 - records_left))
            socketio.emit('scan_progress', {
                'scan_id': scan_id,
                'message': f'Analyzing responses...',
                'progress': progress,
                'phase': 'Passive Scan'
            }, room=session_id)
            time.sleep(2)

        # Final check before processing results
        if scan_id not in active_scans:
            return

        # Process results only if scan wasn't stopped
        alerts = [
            alert for alert in zap.core.alerts()
            if alert.get('url', '').startswith(target_url)
        ]
        results = process_scan_results(alerts)

        if scan_id not in active_scans:
            return

        # Save scan results
        save_scan_results(scan_id, target_url, results, context_name)
        
        # Generate reports
        print(f"[{scan_id}] Calling generate_reports function...")
        print(f"[{scan_id}] Parameters: target_url={target_url}, scan_id={scan_id}, context_name={context_name}")
        try:
            html_file = generate_reports(
                target_url,
                results,
                scan_id,
                context_name,
                socketio,
                session_id
            )
            print(f"[{scan_id}] generate_reports completed successfully, returned: {html_file}")
        except Exception as e:
            error_msg = f"generate_reports failed: {str(e)}"
            print(f"[{scan_id}] ❌ ERROR: {error_msg}")
            # Don't raise here - we want the scan to complete even if report generation fails
            # but we should emit an error to the frontend
            socketio.emit('scan_error', {
                'scan_id': scan_id,
                'error': f"Scan completed but report generation failed: {error_msg}"
            }, room=session_id)
            return  # Exit early since report generation failed

        if scan_id not in active_scans:
            print(f"[{scan_id}] Scan was stopped by user, not sending completion event")
            return

        # Update the completion event to include report URL instead of file path
        report_filename = f"{scan_id}_{target_url.replace('://', '_').replace('/', '_')}.html"
        report_url = f'/reports/{report_filename}'  # URL path instead of file path

        socketio.emit('scan_completed', {
            'scan_id': scan_id,
            'message': 'Scan Completed!',
            'result': results,
            'report_url': report_url,  # Send URL instead of file path
        }, room=session_id)

    except Exception as e:
        error_msg = str(e)
        print(f"[ERROR] Scan {scan_id} failed: {error_msg}")
        if session_id and scan_id in active_scans:
            socketio.emit('scan_error', {
                'scan_id': scan_id,
                'error': error_msg
            }, room=session_id)
    finally:
        if context_name and scan_id in active_scan_contexts:
            try:
                zap.context.remove_context(context_name)
                del active_scan_contexts[scan_id]
                print(f"[+] Cleaned up context {context_name}")
            except Exception as e:
                print(f"[ERROR] Failed to clean up context: {str(e)}")

def save_scan_results(scan_id, target_url, results, context_name=None):
    try:
        # Ensure database tables exist
        db.ensure_tables_exist()

        # Save to database
        conn = db.get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO zap_results 
                    (scan_id, target_url, results, timestamp)
                    VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
                    """, 
                    (scan_id, target_url, json.dumps(results))
                )
            conn.commit()
        finally:
            db.put_connection(conn)

        # Keep existing file storage functionality
        output_dir = "./zap_results"
        os.makedirs(output_dir, exist_ok=True)
        safe_filename = f"{scan_id}_{target_url.replace('://', '_').replace('/', '_')}"
        json_file = f"{output_dir}/{safe_filename}.json"
        
        with open(json_file, 'w') as f:
            json.dump({
                'scan_id': scan_id,
                'context_name': context_name,
                'target_url': target_url,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'results': results
            }, f, indent=4)
            
        # Update marketing summary
        db.update_scan_summary(target_url=target_url)
        
        return json_file
    except Exception as e:
        print(f"[ERROR] Failed to save results: {str(e)}")
        raise

def clean_html_content(html_content):
    """Clean HTML content to remove characters that PostgreSQL cannot handle"""
    if not html_content:
        return ""
    
    original_length = len(html_content)
    
    # Remove null bytes (0x00) - PostgreSQL cannot handle these
    null_byte_count = html_content.count('\x00')
    cleaned_content = html_content.replace('\x00', '')
    
    # Remove other problematic control characters except common ones like \t, \n, \r
    control_char_count = 0
    filtered_chars = []
    for char in cleaned_content:
        if ord(char) >= 32 or char in '\t\n\r':
            filtered_chars.append(char)
        else:
            control_char_count += 1
    
    cleaned_content = ''.join(filtered_chars)
    
    # Ensure the content is valid UTF-8
    try:
        cleaned_content = cleaned_content.encode('utf-8', errors='ignore').decode('utf-8')
    except UnicodeDecodeError:
        # Fallback: replace problematic characters
        cleaned_content = cleaned_content.encode('utf-8', errors='replace').decode('utf-8')
    
    final_length = len(cleaned_content)
    
    # Log what was cleaned if anything was removed
    if null_byte_count > 0 or control_char_count > 0 or final_length != original_length:
        print(f"[DEBUG] HTML content cleaned: original={original_length} chars, "
              f"final={final_length} chars, "
              f"null_bytes_removed={null_byte_count}, "
              f"control_chars_removed={control_char_count}")
    
    return cleaned_content

def generate_reports(target_url, results, scan_id, context_name, socketio, session_id):
    """Generate HTML report and save to database"""
    try:
        print(f"[{scan_id}] Starting report generation...") 
        output_dir = "./zap_reports"
        os.makedirs(output_dir, exist_ok=True)

        # Get results from JSON file
        json_file = f"./zap_results/{scan_id}_{target_url.replace('://', '_').replace('/', '_')}.json"
        if not os.path.exists(json_file):
            raise FileNotFoundError(f"Results file not found: {json_file}")
            
        with open(json_file, 'r') as f:
            saved_results = json.load(f)
            results = saved_results['results']

        # Generate report using ZAP API
        report_endpoint = f"{ZAP_URL}/JSON/reports/action/generate/"
        print(f"[{scan_id}] Calling ZAP API to generate report...")
        
        response = requests.get(
            report_endpoint,
            params={
                'apikey': ZAP_API_KEY,
                'title': f'Vulnerability Scan Report - {target_url}',
                'template': 'risk-confidence-html',
                'sites': target_url,
            },
            headers={'Accept': 'application/json'},
            verify=False,
            timeout=30  # Add timeout
        )
        
        if response.status_code != 200:
            raise Exception(f"Failed to generate report (HTTP {response.status_code}): {response.text}")

        # Get generated HTML file path
        response_data = response.json()
        html_file = response_data.get('generate', '').replace('//', '/')
        
        if not html_file:
            raise Exception(f"ZAP API did not return a file path. Response: {response_data}")
            
        print(f"[{scan_id}] ZAP generated report at: {html_file}")
        
        if not os.path.exists(html_file):
            raise FileNotFoundError(f"Generated HTML report not found at path: {html_file}")

        # Read the report content
        try:
            with open(html_file, 'r', encoding='utf-8') as f:
                html_content = f.read()
        except Exception as e:
            raise Exception(f"Failed to read generated report file: {str(e)}")

        # Verify we have content
        if not html_content or len(html_content) < 100:
            raise Exception(f"Generated report appears to be empty or corrupted (length: {len(html_content) if html_content else 0})")

        print(f"[{scan_id}] Successfully read report content ({len(html_content)} characters)")

        # Updated logo handling with absolute path and error checking
        try:
            # Get absolute path to the logo
            current_dir = os.path.dirname(os.path.abspath(__file__))
            logo_path = os.path.join(current_dir, 'virtuestech_logo.png')
            
            print(f"[DEBUG] Looking for logo at: {logo_path}")
            
            if not os.path.exists(logo_path):
                raise FileNotFoundError(f"Logo file not found at: {logo_path}")
            
            with open(logo_path, 'rb') as img_file:
                logo_base64 = base64.b64encode(img_file.read()).decode('utf-8')
                logo_html = f'<img src="data:image/png;base64,{logo_base64}" alt="VirtuesTech Logo" style="height: 64px; margin-bottom: 1rem;">'
                print("[DEBUG] Successfully embedded logo")
        except Exception as e:
            print(f"[ERROR] Failed to load logo: {str(e)}")
            logo_html = '<!-- Logo failed to load -->'

        # Updated header HTML with embedded logo
        header_html = f"""
        <div class="report-container">
            <header>
                {logo_html}
                <h1>Vulnerability Scan Report</h1>
                <div class="scan-info">
                    <p>Target: {target_url}</p>
                    <p>Date: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
            </header>
            <main>
        """

        # Custom CSS combining normalize.css with our styles
        custom_css = """
        <style>
        /* Normalize CSS Base */
        *, *::after, *::before { box-sizing: border-box; }
        html { line-height: 1.15; -webkit-text-size-adjust: 100%; }
        body { margin: 0; }
        main { display: block; }

        /* Typography Normalization */
        h1 { font-size: 2em; margin: 0.67em 0; }
        pre { font-family: monospace, monospace; font-size: 1em; }
        b, strong { font-weight: bolder; }
        code, kbd, samp { font-family: monospace, monospace; font-size: 1em; }

        /* Custom Theme */
        :root {
            --primary-color: #0369ba;
            --secondary-color: #FF963f;
            --text-color: #333333;
            --border-color: #e5e7eb;
            --background-start: #fff;
            --background-middle: #8ce1d6;
            --background-end: #386095;
        }

        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background: linear-gradient(135deg, #fff 0%, #8ce1d6 15%, #306aa0 60%, #386095 100%);
            margin: 0;
            padding: 2rem;
        }

        /* Container Sizing */
        .report-container {
            max-width: 1200px;  /* Increased from 90ch */
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 16px rgba(0,0,0,0.1);
            overflow: hidden;  /* Contain child elements */
        }

        /* Header Styling */
        header {
            background: var(--primary-color);
            color: white;
            padding: 2rem;
            text-align: center;
        }

        header img {
            height: 64px;
            margin-bottom: 1rem;
        }

        header h1 {
            font-size: 2.5rem;
            margin: 0.5rem 0;
            font-family: Georgia, serif;
        }

        .slogan {
            color: var(--secondary-color);
            font-size: 1.2rem;
            margin-bottom: 0.5rem;
        }

        /* Main Content */
        main {
            padding: 2rem;
        }

        /* Heading Hierarchy */
        h2 { 
            font-size: 1.75rem; 
            color: var(--primary-color);
            margin: 2rem 0 1rem;
            border-bottom: 2px solid var(--secondary-color);
            padding-bottom: 0.5rem;
        }

        h3 { 
            font-size: 1.5rem;
            color: var(--primary-color);
            margin: 1.5rem 0 1rem;
        }

        h4 { 
            font-size: 1.25rem;
            color: var(--text-color);
            margin: 1rem 0;
        }

        /* Table Styling */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1.5rem 0;
            font-size: 0.95rem;
        }

        th {
            background: var(--primary-color);
            color: white;
            padding: 1rem;
            text-align: left;
            border: 1px solid var(--border-color);
        }

        td {
            padding: 1rem;
            border: 1px solid var(--border-color);
            vertical-align: top;
            word-break: break-word;  /* Prevent table overflow */
        }

        tr:nth-child(even) {
            background: #f8f9fa;
        }

        tr:hover {
            background: var(--table-hover);
        }

        /* Alert Sections */
        .alerts-section {
            margin: 2rem 0;
        }

        .alert-high { 
            color: #dc3545; 
            font-weight: bold;
            font-family: monospace, monospace;
        }
        
        .alert-medium { 
            color: var(--secondary-color); 
            font-weight: bold;
            font-family: monospace, monospace;
        }

        .alert-low { 
            color: #6f42c1; 
            font-weight: bold;
            font-family: monospace, monospace;
        }

        .alert-informational { 
            color: #17a2b8; 
            font-weight: bold;
            font-family: monospace, monospace;
        }

        .risk-high { 
            background-color: #f8d7da !important; 
            color: #721c24 !important; 
        }

        .risk-medium { 
            background-color: #fff3cd !important; 
            color: #856404 !important; 
        }

        .risk-low { 
            background-color: #d1ecf1 !important; 
            color: #0c5460 !important; 
        }

        .risk-informational { 
            background-color: #e2e3e5 !important; 
            color: #383d41 !important; 
        }

        /* Responsive tables */
        @media (max-width: 768px) {
            table {
                font-size: 0.85rem;
            }
            
            th, td {
                padding: 0.5rem;
            }
        }

        .scan-info {
            margin-top: 1rem;
            opacity: 0.9;
        }

        .scan-info p {
            margin: 0.25rem 0;
            font-size: 1.1rem;
        }
        </style>
        """

        # Custom JavaScript for interactive features
        custom_js = """
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Add click handlers for expandable sections
            document.querySelectorAll('h2, h3').forEach(header => {
                header.style.cursor = 'pointer';
                header.addEventListener('click', function() {
                    const nextElement = this.nextElementSibling;
                    if (nextElement) {
                        nextElement.style.display = nextElement.style.display === 'none' ? 'block' : 'none';
                    }
                });
            });

            // Enhance risk level rows
            document.querySelectorAll('tr').forEach(row => {
                const riskCell = row.querySelector('.risk-high, .risk-medium, .risk-low');
                if (riskCell) {
                    const riskLevel = riskCell.className.split('-')[1];
                    row.classList.add(`alert-${riskLevel}`);
                }
            });
        });
        </script>
        """

        # Remove ZAP references and replace header
        html_content = re.sub(r'<header.*?</header>', header_html, html_content, flags=re.DOTALL)
        html_content = re.sub(r'Generated with.*?Checkmarx', '', html_content, flags=re.DOTALL)
        html_content = html_content.replace('ZAP', '').replace('Checkmarx', '')

        # Remove context section
        html_content = re.sub(r'<section[^>]*id="contexts".*?</section>', '', html_content, flags=re.DOTALL)
        html_content = re.sub(r'<div[^>]*class="contexts".*?</div>', '', html_content, flags=re.DOTALL)

        # Add custom CSS and JS
        html_content = re.sub(r'</head>', f'{custom_css}\n{custom_js}\n</head>', html_content)

        # Add closing tags at the end of the document
        html_content = html_content.replace('</body>', '</main></div></body>')

        # Clean HTML content
        cleaned_content = clean_html_content(html_content)

        # Save the customized report to file
        safe_filename = f"{scan_id}_{target_url.replace('://', '_').replace('/', '_')}.html"
        custom_html_filename = os.path.join(output_dir, safe_filename)
        
        try:
            with open(custom_html_filename, 'w', encoding='utf-8') as f:
                f.write(cleaned_content)
            print(f"[{scan_id}] Generated HTML report at: {custom_html_filename}")
        except Exception as e:
            raise Exception(f"Failed to save customized report to file: {str(e)}")

        # Save report to database - THIS IS THE CRITICAL PART
        try:
            print(f"[{scan_id}] Ensuring database tables exist...")
            db.ensure_tables_exist()
            
            print(f"[{scan_id}] Getting database connection...")
            conn = db.get_connection()
            
            try:
                with conn.cursor() as cur:
                    print(f"[{scan_id}] Saving report to database for URL: {target_url}")
                    print(f"[{scan_id}] Report content length: {len(cleaned_content)} characters")
                    
                    # Check if report already exists for this scan_id
                    cur.execute("""
                        SELECT COUNT(*) FROM zap_reports 
                        WHERE scan_id = %s AND target_url = %s
                    """, (scan_id, target_url))
                    
                    existing_count = cur.fetchone()[0]
                    if existing_count > 0:
                        print(f"[{scan_id}] Report already exists for this scan, updating...")
                        cur.execute("""
                            UPDATE zap_reports 
                            SET content = %s, timestamp = CURRENT_TIMESTAMP
                            WHERE scan_id = %s AND target_url = %s
                        """, (cleaned_content, scan_id, target_url))
                    else:
                        print(f"[{scan_id}] Inserting new report...")
                        cur.execute("""
                            INSERT INTO zap_reports 
                            (scan_id, target_url, report_type, content, timestamp)
                            VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
                        """, (scan_id, target_url, 'html', cleaned_content))
                    
                conn.commit()
                print(f"[{scan_id}] ✅ Report successfully saved to database!")
                
                # Verify the save by checking the database
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT scan_id, target_url, LENGTH(content) as content_length, timestamp 
                        FROM zap_reports 
                        WHERE scan_id = %s AND target_url = %s
                    """, (scan_id, target_url))
                    
                    verification = cur.fetchone()
                    if verification:
                        print(f"[{scan_id}] ✅ Database verification successful: "
                              f"scan_id={verification[0]}, url={verification[1]}, "
                              f"content_length={verification[2]}, timestamp={verification[3]}")
                    else:
                        raise Exception("Failed to verify report was saved to database")
                        
            except Exception as e:
                print(f"[{scan_id}] ❌ Database insertion failed: {str(e)}")
                conn.rollback()
                raise Exception(f"Database save failed: {str(e)}")
            finally:
                db.put_connection(conn)
                
        except Exception as e:
            # This is critical - if database save fails, we should know about it
            error_msg = f"Failed to save report to database: {str(e)}"
            print(f"[{scan_id}] ❌ CRITICAL ERROR: {error_msg}")
            logger.error(f"[{scan_id}] Database save error: {error_msg}", exc_info=True)
            
            # Still return the file, but log the database failure
            # Don't raise here to avoid breaking the scan, but ensure it's logged
            print(f"[{scan_id}] ⚠️  Report file saved successfully, but database save failed!")

        return custom_html_filename, None

    except Exception as e:
        error_msg = f"Report generation failed: {str(e)}"
        print(f"[{scan_id}] ❌ ERROR: {error_msg}")
        logger.error(f"[{scan_id}] {error_msg}", exc_info=True)
        raise Exception(error_msg)


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
