import argparse
import subprocess
import re
import os
import getpass
import requests
import platform
from time import sleep

class NetstatOutput:
    def __init__(self):
        self.api_key = self.set_api_key()
        self.max_checks_per_minute = 4
        self.checks_counter = 0

    def set_api_key(self):
        os.environ['VT_ApiKey'] = getpass.getpass('Please enter correct API key for VirusTotal: ')
        return os.environ['VT_ApiKey']

    def detect_os(self):
        os_type = platform.system()
        if os_type == 'Windows':
            return True
        else:
            return False
        
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

    def get_ips_from_netstat(self):
        try:
            os_type = self.detect_os()
            if os_type:
                command = 'netstat -ano'  # Poprawiono literówkę w zmiennej command
            else:
                command = 'netstat -tulnpa -4'  # Poprawiono literówkę w zmiennej command
            return self.start_netstat(command)  # Zwracanie wyniku funkcji start_netstat
        except Exception as e:
            print(f'Error occurred while running netstat command: {e}')
            return []

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
                    print(f'Total score for IP {ip}: {malicious_score}/{full_score}')
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
                    self.checks_counter = 0  # Zresetowanie licznika po odczekaniu
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
