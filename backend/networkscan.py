import subprocess
import sys
import datetime
import ipaddress
import os
import platform

def is_public_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.version == 4 and not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast)
    except ValueError:
        return False

def get_nmap_path():
    if platform.system() == "Windows":
        win_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
        if os.path.exists(win_path):
            return win_path
        # Try default install path for 64-bit Windows
        win_path_64 = r"C:\Program Files\Nmap\nmap.exe"
        if os.path.exists(win_path_64):
            return win_path_64
        return "nmap"  # fallback, may work if added to PATH
    else:
        return "nmap"  # On Linux/Mac, assume nmap is in PATH

def run_nmap(command_args):
    try:
        print(f"\n🛰️  Running: {' '.join(command_args)}\n")
        # Use subprocess.Popen to stream output line by line
        with subprocess.Popen(command_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as proc:
            for line in proc.stdout:
                print(line, end='')  # Print each line as it comes
        if proc.returncode not in (0, None):
            print(f"❌ Nmap exited with code {proc.returncode}")
    except Exception as e:
        print(f"❌ Error running Nmap: {e}")

def main():
    print("=== Network Scanner using Nmap ===\n")
    target_ip = input("Enter target PUBLIC IPv4 address: ").strip()

    if not target_ip:
        print("❗ Target IP is required.")
        sys.exit(1)

    if not is_public_ip(target_ip):
        print("❌ Error: Only valid PUBLIC IPv4 addresses are allowed.")
        sys.exit(1)

    nmap_path = get_nmap_path()

    print("\nPerforming Quick Scan (basic info and open ports)...")
    command = [
        nmap_path, "-sS", "-T4", "-F", "-Pn", "-v", target_ip
    ]
    run_nmap(command)

if __name__ == "__main__":
    start = datetime.datetime.now()
    main()
    end = datetime.datetime.now()
    print(f"\n⏱️ Scan completed in {end - start}")