import argparse
import subprocess
import re
import os
import getpass
import requests
import platform
import psutil
import json
import sys
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

        choice = int(input("Enter your choice (1/2/3/4): "))
        return choice


class NetstatOutput:
    def __init__(self):
        
        self.max_checks_per_minute = 4
        self.checks_counter = 0
        self.user = self.get_user()
        self.os_type = self.get_os()
        self.get_default_lists()
        self.user_interface = UserInterface()
        self.user_input = self.user_interface.menu()
    
    def get_user(self):
        if self.user_input == 1:
            self.api_key = self.set_api_key()
        elif self.user_input == 2:
            self.get_process_info()


    def set_api_key(self):
        os.environ['VT_ApiKey'] = getpass.getpass('Please enter correct API key for VirusTotal: ')
        return os.environ['VT_ApiKey']

    def get_user(self):
        return os.getlogin()

    def get_default_lists(self):
        if self.os_type in ['Windows 10', 'Windows 11']:
            self.apps_paths = [
                r'C:\Program Files',
                r'C:\Program Files (x86)',  # Dla aplikacji 32-bitowych na systemach 64-bitowych
                r'C:\Windows\System32',
                r'C:\Windows\SysWOW64'      # Dla aplikacji 32-bitowych na systemach 64-bitowych
            ]
        elif self.os_type == 'Linux':
            pass
        else:
            raise NotImplementedError(f"Unsupported OS: {self.os_type}")

    def get_os(self):
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

    # def get_user_input(self):
    #     skipping = input("[?] Do u want to check ip in v")

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
            print(f'Numer ASN: {asn}')
        
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



def main():
    parser = argparse.ArgumentParser(description='Check IP reputations using VirusTotal API')
    parser.add_argument('--ips', nargs='+', help='List of IP addresses to check')
    args = parser.parse_args()

    if not args.ips:
        netstat = NetstatOutput()
        ip_addresses = netstat.get_ips_from_netstat()
    else:
        ip_addresses = args.ips

    if ip_addresses:
        netstat = NetstatOutput()
        netstat.run_checks(ip_addresses)


if __name__ == "__main__":
    main()
