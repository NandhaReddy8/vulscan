
echo "All sessions have been restarted."

root@srv586371:/home/cybersec/vulscan# cat stop.sh
#!/bin/bash

# Define the screen sessions you want to stop
sessions=("vulscan-backend" "zap")

# Function to kill a screen session
kill_session() {
  session_name=$1
  # Check if the session exists and terminate it
  screen -ls | grep "$session_name" | awk '{print $1}' | xargs -I {} screen -X -S {} quit
  echo "Stopped session: $session_name (if it existed)"
}

# Iterate through each session and kill it
for session in "${sessions[@]}"; do
  kill_session "$session"
done

echo "All specified screen sessions have been stopped."
root@srv586371:/home/cybersec/vulscan#
