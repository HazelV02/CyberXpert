import json
import subprocess

class CyberXpert:
    def __init__(self, attacker_ip, ssh_key_path, target_ip):
        self.working_memory = {
            'tactic': None,
            'technique': None,
            'cvss': None,
            'cve_id': None
        }
        self.attacker_ip = attacker_ip
        self.ssh_key_path = ssh_key_path
        self.target_ip = target_ip
        self.load_knowledge_base()

    def load_knowledge_base(self):
        """Load the knowledge base organized by tactics with their corresponding techniques"""
        self.knowledge_base = {
            "Initial Access": {
                "T1078": {
                    "description": "Exploiting valid accounts.",
                    "tools": [
                        {"name": "Medusa", "command": "medusa -h 192.168.64.128 -U users.txt -P passwords.txt -M ssh"}
                    ],
                    "vulnerability_types": ["Credential Brute-forcing", "Weak Authentication"],
                    "mitigations": [
                        "M1027 - Password Policies",
                        "M1032 - Multi-factor Authentication",
                        "M1049 - Disable or Remove Unnecessary Accounts",
                        "M1056 - Privileged Account Management"
                    ]
                }
            },
            "Credential Access": {
                "T1040": {
                    "description": "Network sniffing to capture credentials.",
                    "tools": [
                        {"name": "bettercap", "command": "./automate_t1040.sh"},
                    ],
                    "vulnerability_types": ["Clear-text Protocol", "Unencrypted Traffic"],
                    "mitigations": [
                        "M1037 - Filter Network Traffic",
                        "M1041 - Encrypt Sensitive Information",
                        "M1036 - Network Intrusion Prevention",
                        "M1050 - Network Segmentation"
                    ]
                }
            },
            "Execution": {
                "T1203": {
                    "description": "Exploitation of general vulnerabilities in applications.",
                    "tools": [
                        {"name": "Metasploit", "command": "./run_automation.sh"}
                    ],
                    "vulnerability_types": ["Application Exploitation"],
                    "mitigations": [
                        "M1042 - Update Software",
                        "M1026 - Application Developer Guidance",
                        "M1038 - Execution Prevention",
                        "M1043 - Disable or Remove Feature or Program"
                    ]
                }
            }
        }

    def set_fact(self, fact_type, value):
        """Set facts in working memory"""
        if fact_type in self.working_memory:
            self.working_memory[fact_type] = value
        else:
            raise ValueError(f"Unknown fact type: {fact_type}")

    def recommend_tool(self):
        """Recommend penetration testing tools based on tactic and technique"""
        technique = self.working_memory.get('technique')
        if not technique:
            return None

        tactic, kb_entry = next(((tactic, techniques[technique]) for tactic, techniques in self.knowledge_base.items() if technique in techniques), (None, None))
        if not kb_entry:
            return None

        tools = kb_entry.get("tools", [])
        highest_priority_tool = tools[0] if tools else None

        return {
            "tactic": tactic,
            "description": kb_entry["description"],
            "recommended_tool": highest_priority_tool,
            "mitigations": kb_entry.get("mitigations", [])
        }

    def conduct_penetration_test(self):
        """Execute the recommended penetration testing tool command via SSH"""
        tool = self.working_memory.get('pentesting_tool')
        if not tool:
            return "No penetration testing tool recommended."

        command = tool.get('command')
        if not command:
            return "No command found for the recommended tool."

        ssh_command = f'ssh -i {self.ssh_key_path} kali@{self.attacker_ip} "{command}"'
        try:
            print(f"Executing remotely: {ssh_command}")
            result = subprocess.run(ssh_command, shell=True, text=True, capture_output=True)
            if result.returncode == 0:
                return f"Penetration testing successful:\n{result.stdout}"
            else:
                return f"Penetration testing failed:\n{result.stderr}"
        except Exception as e:
            return f"Error executing command via SSH: {str(e)}"

    def prioritize_vulnerabilities(self, vulnerabilities):
        """Prioritize vulnerabilities based on CVSS score and entry order."""
        return sorted(vulnerabilities, key=lambda x: (-x['cvss'], vulnerabilities.index(x)))

    def process_vulnerabilities(self, vulnerabilities):
        """Process vulnerabilities in priority order."""
        prioritized = self.prioritize_vulnerabilities(vulnerabilities)
        for vulnerability in prioritized:
            self.set_fact('tactic', vulnerability['tactic'])
            self.set_fact('technique', vulnerability['technique'])
            self.set_fact('cvss', vulnerability['cvss'])
            self.set_fact('cve_id', vulnerability['cve_id'])
            recommendations = self.recommend_tool()
            self.working_memory['pentesting_tool'] = recommendations.get("recommended_tool")
            self.working_memory['recommendation'] = recommendations.get("mitigations")
            print(self.generate_report())
            print(self.conduct_penetration_test())

    def generate_report(self):
        """Generate a report based on the findings and recommendations"""
        return json.dumps({"working_memory": self.working_memory}, indent=2)

# Example usage
if __name__ == "__main__":
    attacker_ip = "192.168.64.129"
    ssh_key_path = "C:\\Users\\Ghassan\\.ssh\\id_ed25519"
    target_ip = "192.168.64.128"

    vulnerabilities = [
         {"tactic": "Execution", "technique": "T1203", "cvss": 9, "cve_id": "CVE-2023-1472"},
        {"tactic": "Initial Access", "technique": "T1078", "cvss": 9.5, "cve_id": "CVE-2021-34527"}
    ]

      #         {"tactic": "Initial Access", "technique": "T1078", "cvss": 9.5, "cve_id": "CVE-2021-34527"},{"tactic": "Credential Access", "technique": "T1040", "cvss": 9, "cve_id": "CVE-2020-1472"}, {"tactic": "Execution", "technique": "T1203", "cvss": 9, "cve_id": "CVE-2023-1472"},

    expert_system = CyberXpert(attacker_ip, ssh_key_path, target_ip)
    expert_system.process_vulnerabilities(vulnerabilities)
