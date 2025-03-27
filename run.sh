#!/bin/bash
echo "Starting MongoDB..."
sudo systemctl start mongod

echo "Activating Python Virtual Environment..."
source backend/allenv/bin/activate

echo "Starting ZAP Proxy..."
nohup zaproxy -daemon -port 8085 -host 127.0.0.1 > logs/zap.log 2>&1 &

echo "Starting Flask Server..."
cd backend
python server.py

echo "System Ready! Access frontend via index.html"
