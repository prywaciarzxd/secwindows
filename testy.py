import argparse
import subprocess
import re
import os
import getpass
import requests
import platform
import psutil
from time import sleep

class UserInterface:
    def __init__(self):
        pass

    def welcome_message(self):
        print("=== Welcome to System Security Check ===")

    def menu(self):
        print("\nMenu:")
        print("1. Check IP reputation of remote addresses we connect to.")
        print("2. Check process paths and parent processes for non-default applications.")
        print("3. Perform baseline check for known safe processes.")
        print("4. Exit")

        choice = input("Enter your choice (1/2/3/4): ")
        return choice

class NetstatOutput:
    def __init__(self):
        self.api_key = None
        self.max_checks_per_minute = 4
        self.checks_counter = 0
        self.user = self.get_user()
        self.os_type = self.detect_os()
        self.create_default_lists()
        self.user_interface = UserInterface()

    def set_api_key(self):
        self.api_key = getpass.getpass('Please enter correct API key for VirusTotal: ')

    def get_user(self):
        return os.getlogin()

    def create_default_lists(self):
        if self.os_type in ['Windows 10', 'Windows 11']:
            self.apps_paths = [
                r'C:\Program Files',
                r'C:\Program Files (x86)',  # For 32-bit applications on 64-bit systems
                r'C:\Windows\System32',
                r'C:\Windows\SysWOW64'      # For 32-bit applications on 64-bit systems
            ]
        elif self.os_type == 'Linux':
            pass
        else:
            raise NotImplementedError(f"Unsupported OS: {self.os_type}")

    def detect_os(self):
        os_type = platform.system()
        os_version = platform.release()
        if os_type == 'Windows':
            if os_version.startswith('10.0.22000'):
                return 'Windows 11'
            else:
                return 'Windows 10'
        else:
            return 'Linux'

    def start_netstat(self, command):
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            netstat_output = stdout.decode()
            ip_addresses = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', netstat_output)
            return [ip for ip in ip_addresses if not (ip.startswith('172.16.') or ip.startswith('192.168.') or ip.startswith('10.0') or ip == '127.0.0.1' or ip == '0.0.0.0')]
        except Exception as e:
            print(f'Error occurred while running netstat command: {e}')
            return []

    def get_process_info(self, pid):
        try:
            process = psutil.Process(pid)
            exe_path = process.exe()
            parent_folder = os.path.dirname(exe_path)
            command = process.cmdline()
            return exe_path, parent_folder, command
        except Exception as e:
            print(f'Error occurred while retrieving process info for PID {pid}: {e}')
            return None, None, None

    def get_ips_from_netstat(self):
        try:
            if self.os_type in ['Windows 10', 'Windows 11']:
                command = 'netstat -ano'
            else:
                command = 'netstat -tulnpa -4'
            ip_addresses = self.start_netstat(command)
            return ip_addresses
        except Exception as e:
            print(f'Error occurred while running netstat command: {e}')
            return []

    def output_ips_owner(self, ip, malicious_score, owner, asn):
        if int(malicious_score) > 0:
            print(f'Owner of IP {ip}: {owner}')
            print(f'ASN Number: {asn}')

    def virustotal_api(self, ip_addresses):
        for ip in ip_addresses:
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
            headers = {'x-apikey': self.api_key}
            try:
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    full_score = sum(data['data']['attributes']['last_analysis_stats'].values())
                    malicious_score = data['data']['attributes']['last_analysis_stats']['malicious']
                    owner = data['data']['attributes']['as_owner']
                    asn = data['data']['attributes']['asn']
                    print(f'Total score for IP {ip}: {malicious_score}/{full_score}')
                    self.output_ips_owner(ip, malicious_score, owner, asn)
                else:
                    print(f"Error: {response.status_code}")
            except Exception as e:
                print(f"Error occurred while querying VirusTotal for IP {ip}: {e}")

    def run_checks(self, ip_addresses):
        for ip in ip_addresses:
            try:
                if self.checks_counter == self.max_checks_per_minute:
                    print("You have reached the API rate limit. Waiting 60 seconds...")
                    sleep(60)
                    self.checks_counter = 0  # Reset the counter after waiting
                self.virustotal_api([ip])
                self.checks_counter += 1
            except Exception as e:
                print(f'Error occurred while processing IP {ip}: {e}')

    def check_processes(self):
        try:
            processes = []
            for process in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'parent']):
                processes.append(process.info)

            return processes
        except Exception as e:
            print(f'Error occurred while retrieving process information: {e}')
            return []

    def baseline_check(self):
        try:
            safe_processes = [
                "explorer.exe", "svchost.exe", "taskhost.exe", "wininit.exe", "lsass.exe", "services.exe",
                "csrss.exe", "smss.exe", "System", "System Idle Process", "Idle", "System", "lsass.exe",
                "spoolsv.exe", "winlogon.exe", "conhost.exe", "dllhost.exe", "wmiapsrv.exe", "wmiprvse.exe",
                "wininit.exe", "winlogon.exe", "svchost.exe", "smss.exe", "taskhost.exe", "vds.exe",
                "taskeng.exe", "alg.exe", "csrss.exe", "spoolsv.exe", "svchost.exe", "lsm.exe", "lsass.exe"
            ]

            processes = self.check_processes()
            for process in processes:
                if process['name'] not in safe_processes:
                    print(f"Non-default process found: {process['name']}")

        except Exception as e:
            print(f'Error occurred while performing baseline check: {e}')

    def handle_ip_reputation_check(self):
        ip_addresses = self.get_ips_from_netstat()
        if ip_addresses:
            self.run_checks(ip_addresses)

    def handle_process_paths_check(self):
        self.check_processes()

    def handle_baseline_check(self):
        self.baseline_check()

    def handle_menu_choice(self, choice):
        if choice == '1':
            self.handle_ip_reputation_check()
        elif choice == '2':
            self.handle_process_paths_check()
        elif choice == '3':
            self.handle_baseline_check()
        elif choice == '4':
            print("Exiting the program. Goodbye!")
        else:
            print("Invalid choice. Please enter a valid option.")

def main():
    netstat = NetstatOutput()
    netstat.user_interface.welcome_message()

    while True:
        choice = netstat.user_interface.menu()

        if choice == '4':
            break

        netstat.handle_menu_choice(choice)

        # Optionally, ask for API key if user chose option 1
        if choice == '1' and not netstat.api_key:
            netstat.set_api_key()

if __name__ == "__main__":
    main()
