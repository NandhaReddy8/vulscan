import importlib
import sys
from flask import request, jsonify

@app.route('/api/reload', methods=['POST'])
def reload_modules():
    """Reload Python modules without restarting the server"""
    try:
        # Reload database module
        if 'backend.database' in sys.modules:
            importlib.reload(sys.modules['backend.database'])
        if 'backend.networkscan' in sys.modules:
            importlib.reload(sys.modules['backend.networkscan'])
        return jsonify({"status": "success", "message": "Modules reloaded successfully"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/network/start-scan', methods=['POST'])
def start_scan():
    try:
        data = request.get_json()
        if not data or 'ip_address' not in data:
            return jsonify({'error': 'Missing IP address'}), 400
            
        ip_address = data['ip_address']
        requester_ip = request.headers.get('X-Requester-IP', request.remote_addr)
            
        success, message, scan_id = start_network_scan(ip_address, requester_ip)
        
        if not success:
            return jsonify({'error': message}), 400
            
        return jsonify({
            'message': message,
            'scan_id': scan_id
        })
        
    except Exception as e:
        logger.error(f"Error in start_scan: {str(e)}")
        return jsonify({'error': str(e)}), 500 