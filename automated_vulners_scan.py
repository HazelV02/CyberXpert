import paramiko
import os
import re
import csv
from prettytable import PrettyTable

# Define connection details
kali_ip = "192.168.64.129"  # Replace with your Kali VM IP
kali_user = "kali"
key_path = "C:/Users/Ghassan/.ssh/id_ed25519"  # Path to your private key
target_ip = "192.168.64.128"  # Replace with your target IP
nmap_output = "/home/kali/Host_nmap_vulners_scan.txt"

# Establish SSH connection
def ssh_connect():
    print("Establishing SSH connection to Kali...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(kali_ip, username=kali_user, key_filename=key_path)
    print("SSH connection established.")
    return ssh

# Run Nmap vulnerability scan with Vulners
def run_vulners_scan(ssh):
    print("Running detailed vulnerability scan using Vulners...")
    vulners_command = f"nmap -A --script vulners -oN {nmap_output} {target_ip}"
    stdin, stdout, stderr = ssh.exec_command(vulners_command)
    for line in iter(stdout.readline, ""):
        print(line.strip())  # Print scan progress
    print("Vulnerability scan completed.")

# Retrieve scan results
def retrieve_results(ssh):
    print("Retrieving scan results from Kali...")
    sftp = ssh.open_sftp()
    local_output = "nmap_vulners_scan.txt"
    sftp.get(nmap_output, local_output)  # Save results to host machine
    sftp.close()
    print(f"Results saved to {local_output}.")
    return local_output

# Parse results for vulnerabilities and save to CSV
def parse_vulners_results(file_path):
    print("Parsing scan results for vulnerabilities...")
    if not os.path.exists(file_path):
        print("Result file not found.")
        return

    vulnerabilities = []
    with open(file_path, "r") as file:
        for line in file:
            line = line.strip()
            # Extract all valid entries (CVE, SSV, POSTGRESQL, etc.)
            match = re.search(r"((CVE-\d{4}-\d+|SSV:\d+|POSTGRESQL:CVE-\d{4}-\d+))\s+([\d.]+)\s+(https://[^\s]+)", line)
            if match:
                vuln_id = match.group(1)
                cvss_score = match.group(3)
                description = match.group(4)
                vulnerabilities.append((vuln_id, cvss_score, description))

    if vulnerabilities:
        print("\nDetected Vulnerabilities:")
        table = PrettyTable(["Vulnerability ID", "CVSS Score", "Description"])
        for vuln in vulnerabilities:
            table.add_row(vuln)
        print(table)
        print(f"\nTotal number of vulnerabilities found: {len(vulnerabilities)}")

        # Save to CSV
        csv_file = "vulnerabilities.csv"
        with open(csv_file, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["Vulnerability ID", "CVSS Score", "Description"])
            writer.writerows(vulnerabilities)
        print(f"Vulnerabilities saved to {csv_file}.")
    else:
        print("No vulnerabilities detected.")

# Main function
def main():
    ssh = ssh_connect()
    try:
        run_vulners_scan(ssh)
        local_output = retrieve_results(ssh)
        parse_vulners_results(local_output)
    finally:
        ssh.close()
        print("SSH connection closed.")

if __name__ == "__main__":
    main()
