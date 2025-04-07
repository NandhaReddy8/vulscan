from zapv2 import ZAPv2
import logging
import os
import time
import re
import base64
import pdfkit
from datetime import datetime
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ZAPReportRetriever:
    def __init__(self):
        """Initialize ZAP connection"""
        try:
            # ZAP API connection settings
            self.zap_api_key = '3ek27hdj10tooh0defcrknlm8o'
            self.zap_url = 'http://127.0.0.1:8080'
            
            # Initialize ZAP connection
            self.zap = ZAPv2(
                apikey=self.zap_api_key,
                proxies={'http': self.zap_url, 'https': self.zap_url}
            )
            
            # Configure PDF conversion settings
            # Check common installation paths for wkhtmltopdf
            # Define possible paths for wkhtmltopdf based on the operating system
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
            
            self.wkhtmltopdf_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    self.wkhtmltopdf_path = path
                    break
                    
            if not self.wkhtmltopdf_path:
                raise Exception("wkhtmltopdf not found. Please install from https://wkhtmltopdf.org/downloads.html")
                
            self.pdf_options = {
                'page-size': 'A4',
                'margin-top': '0.75in',
                'margin-right': '0.75in',
                'margin-bottom': '0.75in',
                'margin-left': '0.75in',
                'encoding': "UTF-8",
                'no-outline': None
            }
            
            # Test connection
            version = self.zap.core.version
            logger.info(f"Successfully connected to ZAP version {version}")
            
        except Exception as e:
            logger.error(f"Failed to initialize: {str(e)}")
            raise

    def clear_session(self):
        """Clear current session data"""
        try:
            # Create new session
            self.zap.core.new_session()
            # Clear existing alerts
            self.zap.core.delete_all_alerts()
            logger.info("Cleared previous session data")
        except Exception as e:
            logger.error(f"Failed to clear session: {str(e)}")
            raise

    def customize_report(self, html_content):
        """Customize the ZAP HTML report"""
        try:
            # Read VirtuesTech logo
            logo_path = os.path.join(os.path.dirname(__file__), 'virtuestech_logo.png')
            if not os.path.exists(logo_path):
                logger.error(f"Logo not found at: {logo_path}")
                return html_content
                
            # Convert logo to base64
            with open(logo_path, 'rb') as f:
                logo_base64 = base64.b64encode(f.read()).decode('utf-8')

            # Add CSS for header and footer
            css_styles = '''
            <style>
                .report-header {
                    text-align: center;
                    margin-bottom: 30px;
                }
                .report-header img {
                    width: 250px;
                    height: auto;
                    display: block;
                    margin: 0 auto 20px auto;
                }
                .report-header h1 {
                    margin-top: 10px;
                    font-size: 24px;
                }
                .footer-logo {
                    position: fixed;
                    bottom: 20px;
                    left: 20px;
                    width: 100px;
                    height: auto;
                }
                @media print {
                    .footer-logo {
                        position: fixed;
                        bottom: 20px;
                        left: 20px;
                        width: 100px;
                        height: auto;
                    }
                    div.footer {
                        position: fixed;
                        bottom: 0;
                    }
                }
            </style>
            '''

            # Create header with VirtuesTech logo
            new_header = f'''
            <div class="report-header">
                <img src="data:image/png;base64,{logo_base64}" alt="VirtuesTech Logo" />
                <h1>Scanning Report</h1>
            </div>
            <p />
            '''

            # Create footer with logo
            footer = f'''
            <div class="footer">
                <img src="data:image/png;base64,{logo_base64}" class="footer-logo" alt="VirtuesTech Logo" />
            </div>
            '''

            # Add CSS to head
            html_content = re.sub(
                r'</head>',
                f'{css_styles}</head>',
                html_content
            )

            # Replace existing header
            html_content = re.sub(
                r'<h1>.*?</h1>\s*<p\s*/>', 
                new_header,
                html_content,
                flags=re.DOTALL
            )

            # Add footer before closing body tag
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

            # Add new title
            html_content = re.sub(
                r'<head>', 
                '<head>\n<title>Scanning Report</title>', 
                html_content
            )

            return html_content

        except Exception as e:
            logger.error(f"Failed to customize report: {str(e)}")
            logger.error(f"Error details: {str(e)}")
            return html_content

    def scan_target(self, target_url):
        """Perform ZAP scan on target"""
        try:
            # Ensure proper URL format
            if not target_url.startswith(('http://', 'https://')):
                target_url = 'http://' + target_url
            
            logger.info(f"Scanning target: {target_url}")
            
            # Access URL through ZAP
            self.zap.urlopen(target_url)
            logger.info("Successfully accessed target through ZAP")
            
            # Wait for passive scan to complete
            while int(self.zap.pscan.records_to_scan) > 0:
                logger.info(f"Records left to scan: {self.zap.pscan.records_to_scan}")
                time.sleep(2)
            
            logger.info("Passive scan completed")
            return True
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            raise

    def convert_to_pdf(self, html_path):
        """Convert HTML report to PDF"""
        try:
            # Configure pdfkit
            config = pdfkit.configuration(wkhtmltopdf=self.wkhtmltopdf_path)
            
            # Generate PDF filename
            pdf_path = html_path.replace('.html', '.pdf')
            
            logger.info("Converting HTML report to PDF...")
            pdfkit.from_file(
                html_path, 
                pdf_path,
                options=self.pdf_options,
                configuration=config
            )
            
            logger.info(f"PDF report saved to: {pdf_path}")
            return pdf_path
            
        except Exception as e:
            logger.error(f"Failed to convert to PDF: {str(e)}")
            raise

    def get_html_report(self, target_url, output_dir='zap_reports'):
        """Generate and retrieve HTML report from ZAP"""
        try:
            # Clear previous session
            self.clear_session()
            
            # Scan target
            self.scan_target(target_url)
            
            # Create output directory
            os.makedirs(output_dir, exist_ok=True)
            
            # Generate filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_url = urlparse(target_url).netloc
            filename = f'zap_report_{safe_url}_{timestamp}.html'
            filepath = os.path.join(output_dir, filename)
            
            # Get and customize report
            logger.info("Generating HTML report...")
            report_html = self.zap.core.htmlreport()
            report_html = self.customize_report(report_html)
            
            # Save HTML report
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(report_html)
            
            logger.info(f"HTML report saved to: {filepath}")
            
            # Convert to PDF
            pdf_path = self.convert_to_pdf(filepath)
            
            return filepath, pdf_path
            
        except Exception as e:
            logger.error(f"Failed to generate report: {str(e)}")
            raise

def main():
    # Target URL to scan
    target_url = "https://thethrone.in"
    
    try:
        # Create scanner instance
        retriever = ZAPReportRetriever()
        
        # Generate reports
        html_path, pdf_path = retriever.get_html_report(target_url)
        
        # Verify reports
        if os.path.exists(html_path) and os.path.exists(pdf_path):
            html_size = os.path.getsize(html_path)
            pdf_size = os.path.getsize(pdf_path)
            logger.info(f"HTML Report generated successfully ({html_size} bytes)")
            logger.info(f"PDF Report generated successfully ({pdf_size} bytes)")
            logger.info(f"Reports location:\nHTML: {html_path}\nPDF: {pdf_path}")
        else:
            logger.error("Report files not found!")
            
    except Exception as e:
        logger.error(f"Script execution failed: {str(e)}")

if __name__ == "__main__":
    main()