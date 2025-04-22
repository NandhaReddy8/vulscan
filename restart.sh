#!/bin/bash

# Define the screen sessions and their respective commands
declare -A sessions=(
  ["vulscan-backend"]="python3 -m venv venv && . venv/bin/activate && pip install -r requirements.txt && cd backend && python server.py"
  ["zap"]="zaproxy -daemon -port 8080 -host 127.0.0.1"
)

# Function to kill a screen session
kill_session() {
  session_name=$1
  screen -ls | grep "$session_name" | awk '{print $1}' | xargs -I {} screen -X -S {} quit
  echo "Killed session: $session_name (if it existed)"
}

# Restart each session
for session in "${!sessions[@]}"; do
  # Kill the existing session
  kill_session "$session"

  # Start a new session
  screen -dmS "$session" bash -c "${sessions[$session]}"
  echo "Started new session: $session with command: ${sessions[$session]}"
done

echo "All sessions have been restarted."
