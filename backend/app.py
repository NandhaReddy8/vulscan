import importlib
import sys
from flask import Flask, request, jsonify

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