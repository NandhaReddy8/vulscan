import os
import requests
import json
import logging
from datetime import datetime
from dotenv import load_dotenv
from urllib.parse import urlparse

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

class DojoHandler:
    def __init__(self):
        self.base_url = os.getenv('DOJO_URL')
        self.api_key = os.getenv('DOJO_API_KEY')
        
        if not self.base_url or not self.api_key:
            raise ValueError("DefectDojo URL or API key not found in environment variables")
            
        self.headers = {
            'Authorization': f'Token {self.api_key}',
            'Content-Type': 'application/json'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.verify = False  # For self-signed certificates

    def authenticate(self):
        """Test authentication with DefectDojo"""
        try:
            response = self.session.get(f"{self.base_url}/api/v2/users/")
            if response.status_code == 200:
                logger.info("Successfully authenticated with DefectDojo")
                return True
            else:
                logger.error(f"Authentication failed: {response.text}")
                return False
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return False

    def get_product(self, product_name):
        """Get or create a product in DefectDojo"""
        try:
            # Standardize product name to ensure consistency
            product_name = "VirtuesTech Scanner"  # Use a fixed name for all scans
            
            print(f"[DefectDojo] Looking up product: {product_name}")
            response = self.session.get(
                f"{self.base_url}/api/v2/products/?name={product_name}"
            )
            products = response.json()
            
            if products['results']:
                product_id = products['results'][0]['id']
                print(f"[DefectDojo] Found existing product with ID: {product_id}")
                return product_id
            
            # Create new product if not found
            product_data = {
                'name': product_name,
                'description': 'VirtuesTech Scanner Products',
                'prod_type': 1
            }
            response = self.session.post(
                f"{self.base_url}/api/v2/products/",
                json=product_data
            )
            product_id = response.json()['id']
            print(f"[DefectDojo] Created new product with ID: {product_id}")
            return product_id
            
        except Exception as e:
            logger.error(f"Error getting/creating product: {str(e)}")
            raise

    def get_engagement(self, product_id, target_url):
        """Get or create an engagement for the scan"""
        try:
            engagement_name = f"Scan for {target_url}"
            
            # Check existing engagements
            response = self.session.get(
                f"{self.base_url}/api/v2/engagements/?product={product_id}&name={engagement_name}"
            )
            engagements = response.json()
            
            if engagements['results']:
                return engagements['results'][0]['id']
            
            # Create new engagement
            engagement_data = {
                'name': engagement_name,
                'product': product_id,
                'target_start': datetime.now().strftime('%Y-%m-%d'),
                'target_end': datetime.now().strftime('%Y-%m-%d'),
                'status': 'In Progress'
            }
            response = self.session.post(
                f"{self.base_url}/api/v2/engagements/",
                json=engagement_data
            )
            return response.json()['id']
            
        except Exception as e:
            logger.error(f"Error getting/creating engagement: {str(e)}")
            raise

    def get_or_create_endpoint(self, product_id, target_url):
        """Create or get existing endpoint for the target URL"""
        try:
            parsed_url = urlparse(target_url)
            host = parsed_url.netloc
            protocol = parsed_url.scheme
            
            print(f"[DefectDojo] Looking up endpoint for {host}")
            
            # Search for existing endpoint
            response = self.session.get(
                f"{self.base_url}/api/v2/endpoints/",
                params={
                    'host': host,
                    'product': product_id
                }
            )
            endpoints = response.json()
            
            if endpoints['results']:
                endpoint_id = endpoints['results'][0]['id']
                print(f"[DefectDojo] Found existing endpoint with ID: {endpoint_id}")
                return endpoint_id
                
            # Create new endpoint
            endpoint_data = {
                'product': product_id,
                'host': host,
                'protocol': protocol,
                'path': parsed_url.path or '/',
                'query': parsed_url.query,
                'fragment': parsed_url.fragment,
                'port': parsed_url.port or (443 if protocol == 'https' else 80)
            }
            
            response = self.session.post(
                f"{self.base_url}/api/v2/endpoints/",
                json=endpoint_data
            )
            
            if response.status_code == 201:
                endpoint_id = response.json()['id']
                print(f"[DefectDojo] Created new endpoint with ID: {endpoint_id}")
                return endpoint_id
            else:
                raise Exception(f"Failed to create endpoint: {response.text}")
                
        except Exception as e:
            logger.error(f"Error managing endpoint: {str(e)}")
            raise

    def upload_scan(self, engagement_id, xml_file_path, scan_type="ZAP Scan"):
        """Upload XML scan results to DefectDojo"""
        try:
            print(f"[DefectDojo] Reading XML file: {xml_file_path}")
            
            with open(xml_file_path, 'rb') as f:
                files = {
                    'file': (
                        os.path.basename(xml_file_path),
                        f,
                        'application/xml'
                    )
                }
                
                # Get product_id from engagement
                engagement_response = self.session.get(
                    f"{self.base_url}/api/v2/engagements/{engagement_id}/"
                )
                product_id = engagement_response.json()['product']
                
                # Get target URL from filename
                filename = os.path.basename(xml_file_path)
                target_url = filename.split('_', 1)[1].replace('_', '://').rsplit('.xml', 1)[0]
                
                # Create or get endpoint
                endpoint_id = self.get_or_create_endpoint(product_id, target_url)
                
                data = {
                    'engagement': engagement_id,
                    'scan_type': scan_type,
                    'active': True,
                    'verified': True,
                    'close_old_findings': False,
                    'push_to_jira': False,
                    'endpoints': [endpoint_id]  # Associate scan with endpoint
                }
                
                upload_headers = self.headers.copy()
                upload_headers.pop('Content-Type', None)
                
                print(f"[DefectDojo] Uploading to engagement ID: {engagement_id}")
                response = requests.post(
                    f"{self.base_url}/api/v2/import-scan/",
                    headers=upload_headers,
                    files=files,
                    data=data,
                    verify=False
                )
                
                if response.status_code == 201:
                    scan_data = response.json()
                    test_id = scan_data.get('test')
                    
                    if test_id:
                        print(f"[DefectDojo] Upload successful. Test ID: {test_id}")
                        return {
                            'success': True,
                            'scan_id': test_id,
                            'test_id': test_id,
                            'endpoint_id': endpoint_id,
                            'message': 'Scan uploaded successfully'
                        }
                    else:
                        raise KeyError("Test ID not found in response")
                else:
                    error = f"Upload failed (Status {response.status_code}): {response.text}"
                    print(f"[DefectDojo] Error: {error}")
                    return {
                        'success': False,
                        'message': error
                    }
                    
        except Exception as e:
            error = f"Error uploading scan: {str(e)}"
            print(f"[DefectDojo] Error: {error}")
            logger.error(error, exc_info=True)
            return {
                'success': False,
                'message': error
            }

    def process_scan(self, target_url, xml_file_path):
        """Process a complete scan workflow"""
        try:
            print("\n=== DefectDojo Integration Started ===")
            print(f"[DefectDojo] Processing scan for {target_url}")
            print(f"[DefectDojo] Using XML file: {xml_file_path}")
            
            if not os.path.exists(xml_file_path):
                error = f"XML file not found: {xml_file_path}"
                print(f"[DefectDojo] Error: {error}")
                raise FileNotFoundError(error)

            print("[DefectDojo] Authenticating...")
            if not self.authenticate():
                error = "Failed to authenticate with DefectDojo"
                print(f"[DefectDojo] Error: {error}")
                return {'success': False, 'message': error}

            print("[DefectDojo] Authentication successful")

            # Get or create product
            print("[DefectDojo] Getting/creating product...")
            product_id = self.get_product(target_url)
            print(f"[DefectDojo] Using product ID: {product_id}")
            
            # Get or create engagement
            print("[DefectDojo] Getting/creating engagement...")
            engagement_id = self.get_engagement(product_id, target_url)
            print(f"[DefectDojo] Using engagement ID: {engagement_id}")
            
            # Upload scan results
            print("[DefectDojo] Uploading scan results...")
            upload_result = self.upload_scan(engagement_id, xml_file_path)
            
            if upload_result['success']:
                upload_result['dojo_url'] = (
                    f"{self.base_url}/test/{upload_result['test_id']}"
                )
                print(f"[DefectDojo] Success! Report available at: {upload_result['dojo_url']}")
            else:
                print(f"[DefectDojo] Upload failed: {upload_result['message']}")
            
            print("=== DefectDojo Integration Completed ===\n")
            return upload_result
            
        except Exception as e:
            error_msg = f"DefectDojo processing error: {str(e)}"
            print(f"[DefectDojo] Fatal error: {error_msg}")
            logger.error(error_msg, exc_info=True)
            print("=== DefectDojo Integration Failed ===\n")
            return {
                'success': False,
                'message': error_msg
            }