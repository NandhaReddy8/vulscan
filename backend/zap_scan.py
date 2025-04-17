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
from weasyprint import HTML, CSS
from weasyprint.text.fonts import FontConfiguration

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

def scan_target(target_url, socketio, scan_id, active_scans):
    """Perform scan with isolated context"""
    session_id = None
    context_name = None
    
    try:
        session_id = active_scans.get(scan_id)
        if not session_id:
            raise Exception("No session ID found for scan")

        # Create isolated context for this scan
        context_name = create_scan_context(scan_id, target_url)
        
        # Spider scan with context
        print(f"[*] Starting spider scan for context {context_name}")
        spider_scan_id = zap.spider.scan(
            url=target_url,
            contextname=context_name
        )
        
        while int(zap.spider.status(spider_scan_id)) < 100:
            progress = int(zap.spider.status(spider_scan_id))
            socketio.emit('scan_progress', {
                'scan_id': scan_id,
                'message': f'Discovering site structure...',
                'progress': progress,
                'phase': 'Spider Scan'
            }, room=session_id)
            time.sleep(2)

        # Passive scan
        print(f"[*] Starting passive scan for context {context_name}")
        zap.pscan.enable_all_scanners()
        
        while int(zap.pscan.records_to_scan) > 0:
            records_left = int(zap.pscan.records_to_scan)
            progress = max(50, min(95, 100 - records_left))
            socketio.emit('scan_progress', {
                'scan_id': scan_id,
                'message': f'Analyzing responses...',
                'progress': progress,
                'phase': 'Passive Scan'
            }, room=session_id)
            time.sleep(2)

        # Get alerts specific to this context
        alerts = [
            alert for alert in zap.core.alerts()
            if alert.get('url', '').startswith(target_url)
        ]
        results = process_scan_results(alerts)

        # Save results with context information
        save_scan_results(target_url, results, scan_id, context_name)
        
        # Generate reports
        html_file, pdf_file = generate_reports(
            target_url, 
            results, 
            scan_id, 
            context_name
        )

        socketio.emit('scan_completed', {
            'scan_id': scan_id,
            'message': 'Scan Completed!',
            'result': results,
            'html_report': html_file,
            'pdf_report': pdf_file
        }, room=session_id)

        return results

    except Exception as e:
        error_msg = str(e)
        print(f"[ERROR] Scan {scan_id} failed: {error_msg}")
        if session_id:
            socketio.emit('scan_error', {
                'scan_id': scan_id,
                'error': error_msg
            }, room=session_id)
    finally:
        # Clean up context
        if context_name and scan_id in active_scan_contexts:
            try:
                zap.context.remove_context(context_name)
                del active_scan_contexts[scan_id]
                print(f"[+] Cleaned up context {context_name}")
            except Exception as e:
                print(f"[ERROR] Failed to clean up context: {str(e)}")
        
        if session_id:
            active_scans.pop(scan_id, None)

def save_scan_results(target_url, results, scan_id, context_name):
    """Save scan results with context information"""
    try:
        output_dir = "./zap_results"
        os.makedirs(output_dir, exist_ok=True)
        
        # Create filename with scan_id
        safe_filename = f"{scan_id}_{target_url.replace('://', '_').replace('/', '_')}"
        
        # Save results with metadata
        results_with_meta = {
            'scan_id': scan_id,
            'context_name': context_name,
            'target_url': target_url,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'results': results
        }
        
        json_file = f"{output_dir}/{safe_filename}.json"
        with open(json_file, 'w') as f:
            json.dump(results_with_meta, f, indent=4)
            
        return json_file
    except Exception as e:
        print(f"[ERROR] Failed to save results: {str(e)}")
        raise

def generate_reports(target_url, results, scan_id, context_name):
    """Generate HTML and PDF reports for the scan"""
    try:
        output_dir = "./zap_reports"
        os.makedirs(output_dir, exist_ok=True)
        
        safe_filename = f"{scan_id}_{target_url.replace('://', '_').replace('/', '_')}"
        
        # Generate HTML report
        html_report = zap.core.htmlreport()
        html_file = f"{output_dir}/{safe_filename}.html"
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(customize_report(html_report))
            
        # Generate PDF
        pdf_file = f"{output_dir}/{safe_filename}.pdf"
        generate_pdf_from_html(html_file, pdf_file)
        
        return html_file, pdf_file
    except Exception as e:
        print(f"[ERROR] Failed to generate reports: {str(e)}")
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

def customize_report(html_content):
    """Customize the ZAP HTML report to update the header and footer while removing ZAP-specific content."""
    try:
        # Read VirtuesTech logo
        logo_path = os.path.join(os.path.dirname(__file__), 'virtuestech_logo.png')
        if not os.path.exists(logo_path):
            logger.error(f"Logo not found at: {logo_path}")
            return html_content

        # Convert logo to base64
        with open(logo_path, 'rb') as f:
            logo_base64 = base64.b64encode(f.read()).decode('utf-8')

        # Add CSS for styling header and footer
        css_styles = '''
        <style>
            .report-header {
                text-align: center;
                background-color: #f9f9f9;
                color: black;
                padding: 10px 0;
                border-bottom: 2px solid #004080;
            }
            .report-header img {
                width: 300px;
                height: auto;
                margin: 0 auto;
            }
            .report-header h1 {
                margin: 0;
                font-size: 28px;
                color: black;
            }
            .footer {
                text-align: center;
                margin-top: 30px;
                font-size: 12px;
                color: #666;
            }
            .footer-logo {
                width: 150px;
                height: auto;
                margin-top: 10px;
            }
        </style>
        '''

        # Define new header
        new_header = f'''
        <div class="report-header">
            <img src="data:image/png;base64,{logo_base64}" alt="VirtuesTech Logo" />
            <h1>Vulnerability Scan Report</h1>
        </div>
        '''

        # Define footer
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
            r'<body.*?>',
            f'<body>{new_header}',
            html_content,
            flags=re.DOTALL
        )

        # Add footer before the closing body tag
        html_content = re.sub(
            r'</body>',
            f'{footer}</body>',
            html_content
        )

        # Remove the specific ZAP h1 tag with logo
        html_content = re.sub(
            r'<h1>\s*<img[^>]*>ZAP Scanning Report\s*</h1>',
            '',
            html_content,
            flags=re.DOTALL
        )
        # Remove other ZAP-specific content
        zap_patterns = [
            r'<h3>\s*ZAP Version:.*?</h3>',
            r'<h4>\s*ZAP by.*?</h4>',
            r'<title>ZAP.*?</title>',
            r'<div class="header.*?</div>',
            r'<h1>.*?</h1>',
        ]
        for pattern in zap_patterns:
            html_content = re.sub(pattern, '', html_content, flags=re.DOTALL)

        # Add a new title to the report
        html_content = re.sub(
            r'<head>',
            '<head>\n<title>Vulnerability Scan Report</title>',
            html_content
        )

        return html_content

    except Exception as e:
        logger.error(f"Failed to customize report: {str(e)}")
        return html_content


# Function to generate PDF from HTML
def generate_pdf_from_html(html_file, pdf_file):
    """Generate a PDF from an HTML file using WeasyPrint."""
    try:
        print(f"[*] Starting PDF generation for {html_file}")
        
        # Configure fonts
        font_config = FontConfiguration()
        
        # Read the HTML file
        with open(html_file, 'r', encoding='utf-8') as f:
            html_content = f.read()

        # Add print-specific CSS with better table handling
        css = CSS(string='''
            @page {
                margin: 2cm;
                size: A4;
                @bottom-right {
                    content: counter(page);
                    font-size: 12px;
                    padding: 1em;
                }
            }
            body {
                font-family: Arial, sans-serif;
                line-height: 1.5;
                font-size: 12px;
            }
            table {
                width: 100%;
                margin: 1em 0;
                border-collapse: collapse;
                page-break-inside: avoid;
            }
            th, td {
                padding: 8px;
                border: 1px solid #ddd;
                word-break: break-word;
            }
            th {
                background-color: #f5f5f5;
            }
            .report-header {
                text-align: center;
                margin-bottom: 2em;
                break-inside: avoid;
            }
            h1, h2, h3 {
                break-after: avoid;
            }
            img {
                max-width: 100%;
                height: auto;
            }
        ''', font_config=font_config)

        # Generate PDF with optimizations
        HTML(string=html_content).write_pdf(
            pdf_file,
            stylesheets=[css],
            font_config=font_config,
            optimize_size=('fonts', 'images'),
            zoom=1,
            presentational_hints=True
        )

        print(f"[+] PDF report saved to {pdf_file}")
        return True

    except Exception as e:
        print(f"[ERROR] Failed to generate PDF: {str(e)}")
        logger.error(f"PDF generation failed: {str(e)}")
        raise
