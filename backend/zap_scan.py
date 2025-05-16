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
import eventlet
import eventlet.tpool
from weasyprint import HTML, CSS
from weasyprint.text.fonts import FontConfiguration
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
        html_file = generate_reports(
            target_url,
            results,
            scan_id,
            context_name,
            socketio,
            session_id
        )

        if scan_id not in active_scans:
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

def generate_reports(target_url, results, scan_id, context_name, socketio, session_id):
    try:
        print(f"[{scan_id}] Starting report generation...") 
        output_dir = "./zap_reports"
        os.makedirs(output_dir, exist_ok=True)

        # Get results from JSON file
        json_file = f"./zap_results/{scan_id}_{target_url.replace('://', '_').replace('/', '_')}.json"
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
            verify=False
        )
        
        if response.status_code != 200:
            raise Exception(f"Failed to generate report: {response.text}")

        # Get generated HTML file path
        html_file = response.json().get('generate', '').replace('//', '/')
        if not html_file or not os.path.exists(html_file):
            raise FileNotFoundError(f"Generated HTML report not found at path: {html_file}")

        # Read the report content
        with open(html_file, 'r', encoding='utf-8') as f:
            html_content = f.read()

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
                print("[DEBUG] Successfully loaded and encoded logo")
        
        except Exception as logo_error:
            print(f"[ERROR] Failed to load logo: {str(logo_error)}")
            logo_base64 = ""

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
            color: var(--primary-color); 
            font-weight: bold;
            font-family: monospace, monospace;
        }

        /* Code/Pre Formatting */
        pre {
            margin: 0;
            padding: 1rem;
            background: #f8f9fa;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            overflow-x: auto;
        }

        code {
            font-family: monospace, monospace;
            font-size: 0.95em;
        }

        /* Responsive Design */
        @media screen and (max-width: 1200px) {
            body { padding: 1rem; }
            .report-container { margin: 0 1rem; }
            table { font-size: 0.9rem; }
            td, th { padding: 0.75rem; }
        }

        @media screen and (max-width: 768px) {
            header h1 { font-size: 2rem; }
            h2 { font-size: 1.5rem; }
            h3 { font-size: 1.25rem; }
            h4 { font-size: 1.1rem; }
            td, th { padding: 0.5rem; }
        }

        /* Alert Table Styling */
        .alerts-table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            margin: 1.5rem 0;
            border: 1px solid var(--border-color);
            background: white;
        }

        .alerts-table th {
            background: var(--primary-color);
            color: white;
            padding: 1rem;
            text-align: left;
            border: 1px solid var(--border-color);
            font-weight: 600;
        }

        .alerts-table td {
            padding: 1rem;
            border: 1px solid var(--border-color);
            background: white;  /* Force white background */
            color: var(--text-color);  /* Force dark text color */
        }

        /* Risk Level Colors with White Background */
        .alert-high { 
            color: #dc3545; 
            font-weight: bold;
            font-family: monospace, monospace;
            background: white;
        }
        
        .alert-medium { 
            color: var(--secondary-color); 
            font-weight: bold;
            font-family: monospace, monospace;
            background: white;
        }
        
        .alert-low { 
            color: var(--primary-color); 
            font-weight: bold;
            font-family: monospace, monospace;
            background: white;
        }

        /* Alert Type Table Specific */
        .alert-types-table th {
            background: var(--primary-color);
            color: white;
        }

        .alert-types-table td {
            background: white;
            color: var(--text-color);
        }

        /* Ensure links in tables are visible */
        .alerts-table a,
        .alert-types-table a {
            color: var(--primary-color);
            text-decoration: underline;
        }

        .alerts-table a:hover,
        .alert-types-table a:hover {
            color: var(--secondary-color);
        }

        /* Table Row Hover Effect */
        .alerts-table tr:hover td,
        .alert-types-table tr:hover td {
            background: rgba(3, 105, 186, 0.05);
        }

        /* Alert Type Table Specific - Force White Background */
        .alert-type-counts-table td {
            background-color: white !important;  /* Force white background */
            color: white !important;  /* Force text color */
            border: 1px solid var(--border-color);
            padding: 1rem;
        }

        .alert-type-counts-table th {
            background: white;
            color: white;
            padding: 1rem;
            text-align: left;
            border: 1px solid var(--border-color);
        }

        .alert-type-counts-table tr:hover td {
            background-color: rgba(3, 105, 186, 0.02) !important;
        }

        /* Hide Context Section */
        #contexts, 
        .contexts,
        section[id*="context"],
        div[class*="context"] {
            display: none !important;
        }

        /* Alert Type Table Specific - Blue Background with White Text */
        .alert-type-counts-table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            margin: 1.5rem 0;
            border: 1px solid var(--border-color);
        }

        /* Header row - Primary color background */
        .alert-type-counts-table tr:first-child th {
            background-color: var(--primary-color) !important;
            color: white !important;
            padding: 1rem;
            text-align: left;
            border: 1px solid var(--border-color);
            font-weight: 600;
        }

        /* All cells including first column - White background */
        .alert-type-counts-table td,
        .alert-type-counts-table td:first-child {
            background-color: white !important;
            color: var(--text-color) !important;
            border: 1px solid var(--border-color);
            padding: 1rem;
        }

        /* Links in table cells */
        .alert-type-counts-table td a {
            color: var(--primary-color) !important;
            text-decoration: none;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            margin: 0 0.2rem;
            display: inline-block;
        }

        /* Hover effects */
        .alert-type-counts-table tr:hover td {
            background-color: #f8f9fa !important;
        }
        </style>
        """

        # Custom JavaScript
        custom_js = """
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Add collapsible functionality to sections
            document.querySelectorAll('.section h2').forEach(header => {
                header.style.cursor = 'pointer';
                header.addEventListener('click', () => {
                    const content = header.parentElement.querySelector('.section-content');
                    if (content) {
                        const isHidden = content.style.display === 'none';
                        content.style.display = isHidden ? 'block' : 'none';
                        header.classList.toggle('collapsed', !isHidden);
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

        # Load and embed logo directly in HTML
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            logo_path = os.path.join(current_dir, 'virtuestech_logo.png')
            
            print(f"[DEBUG] Loading logo from: {logo_path}")
            
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

        # Save the customized report
        safe_filename = f"{scan_id}_{target_url.replace('://', '_').replace('/', '_')}.html"
        custom_html_filename = os.path.join(output_dir, safe_filename)
        with open(custom_html_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"[{scan_id}] Generated HTML report at: {custom_html_filename}")

        # Save report to database
        try:
            conn = db.get_connection()
            try:
                with conn.cursor() as cur:
                    print(f"[DEBUG] Saving report to database for URL: {target_url}")
                    cur.execute("""
                        INSERT INTO zap_reports 
                        (scan_id, target_url, report_type, content, timestamp)
                        VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
                        """, 
                        (scan_id, target_url, 'html', html_content)
                    )
                conn.commit()
                print(f"[{scan_id}] Report saved to database")
            except Exception as e:
                print(f"[ERROR] Database insertion failed: {str(e)}")
                conn.rollback()
                raise
            finally:
                db.put_connection(conn)
        except Exception as e:
            print(f"[ERROR] Failed to save report to database: {str(e)}")

        return custom_html_filename, None

    except Exception as e:
        print(f"[{scan_id}] [ERROR] Report generation failed: {str(e)}")
        logger.error(f"Report generation failed: {str(e)}", exc_info=True)
        raise


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
