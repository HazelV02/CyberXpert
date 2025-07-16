import paramiko
import time

# Define connection details
kali_ip = "192.168.64.129"  # Replace with your Kali VM IP
kali_user = "kali"
key_path = "C:/Users/Ghassan/.ssh/id_ed25519"  # Path to your private key
target_ip = "192.168.64.128"  # Replace with your target IP
nmap_output = "/home/kali/Host_nmap_results.txt"

# Establish SSH connection
def ssh_connect():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(kali_ip, username=kali_user, key_filename=key_path)
    return ssh

# Run Nmap scan
def run_nmap(ssh):
    print("Running Nmap scan...")
    nmap_command = f"nmap -A -oN {nmap_output} {target_ip}"
    stdin, stdout, stderr = ssh.exec_command(nmap_command)
    for line in iter(stdout.readline, ""):
        print(line.strip())  # Print scan progress
    print("Nmap scan completed.")

# Retrieve scan results
def retrieve_results(ssh):
    print("Retrieving Nmap results...")
    sftp = ssh.open_sftp()
    sftp.get(nmap_output, "nmap_results.txt")  # Save to host machine
    sftp.close()
    print("Results saved as nmap_results.txt.")

# Main function
def main():
    ssh = ssh_connect()
    try:
        run_nmap(ssh)
        retrieve_results(ssh)
    finally:
        ssh.close()
        print("SSH connection closed.")

if __name__ == "__main__":
    main()
