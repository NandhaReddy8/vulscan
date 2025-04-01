#!/bin/bash

echo "Shutting down services..."

# Kill ZAP
pkill -f zaproxy

# Kill Backend
pkill -f 'python server.py'

# Kill Frontend
pkill -f 'vite'

echo "All services stopped."