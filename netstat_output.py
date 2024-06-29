import subprocess
import re
import platform
import psutil
import requests
from time import sleep

class NetstatOutput:
    def __init__(self, api_key):
        self.os_type = platform.system()
        self.command = self.get_netstat_command()
        self.max_checks_per_minute = 4
        self.checks_counter = 0
        self.api_key = api_key

    def start_netstat(self, command):
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            netstat_output = stdout.decode()
            return netstat_output
        except Exception as e:
            print(f'Error occurred while running netstat command: {e}')
            return ""

    def get_netstat_command(self):
        if self.os_type == 'Windows':
            return 'netstat -ano'
        elif self.os_type == 'Linux':
            return 'netstat -tulnpa -4'
        else:
            raise NotImplementedError(f"Unsupported OS: {self.os_type}")

    def get_ips_from_netstat(self):
        try:
            netstat_output = self.start_netstat(self.command)
            ip_port_pairs = re.findall(r'(\b(?:\d{1,3}\.){3}\d{1,3}\b:\d+)', netstat_output)
            ip_ports = [(item.split(':')[0], item.split(':')[1]) for item in ip_port_pairs]
            return [(ip, port) for ip, port in ip_ports if not (ip.startswith('172.16.') or ip.startswith('192.168.') or ip.startswith('10.0') or ip == '127.0.0.1' or ip == '0.0.0.0')]
        except Exception as e:
            print(f'Error occurred while running netstat command: {e}')
            return []

    def get_pids_from_netstat(self):
        try:
            netstat_output = self.start_netstat(self.command)
            pids = set()
            if self.os_type == 'Windows':
                pid_matches = re.findall(r'\s+(\d+)\s*$', netstat_output, re.MULTILINE)
                pids = {match.strip() for match in pid_matches}
            else:
                pid_matches = re.findall(r'\s+(\d+)/[^ ]+', netstat_output)
                pids = {match.strip() for match in pid_matches}
            return list(pids)
        except Exception as e:
            print(f'Error occurred while running netstat command: {e}')
            return []

    def output_ips_owner(self, ip, port, malicious_score, owner, asn):
        if malicious_score > 0:
            print(f'Owner of IP {ip}:{port}: {owner}')
            print(f'Numer ASN: {asn}')
            print(f'Malicious score is: {malicious_score}')
        else:
            print(f'Malicious score of IP {ip}:{port} is: {malicious_score} (Owner: {owner})')

    def virustotal_api(self, ip_port_pairs):
        for ip, port in ip_port_pairs:
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
            headers = {'x-apikey': self.api_key}
            try:
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    malicious_score = data['data']['attributes']['last_analysis_stats']['malicious']
                    owner = data['data']['attributes']['as_owner']
                    asn = data['data']['attributes']['asn']
                    self.output_ips_owner(ip, port, malicious_score, owner, asn)
                    if malicious_score > 0:
                        pids = self.get_pids_for_ip(ip)
                        self.process_pids(pids)
                else:
                    print(f"Error: {response.status_code}")
            except Exception as e:
                print(f"Error occurred while querying VirusTotal for IP {ip}:{port}: {e}")

    def get_pids_for_ip(self, ip):
        netstat_output = self.start_netstat(self.command)
        pid_matches = re.findall(fr'\b{re.escape(ip)}:(\d+)\b', netstat_output)
        return list(set(pid_matches))

    def process_pids(self, pids):
        for pid in pids:
            try:
                process = psutil.Process(int(pid))
                process_name = process.name()
                process_exe = process.exe()
                process_parent = process.parent()
                print(f"PID {pid}: Name={process_name}, Exe={process_exe}, Parent={process_parent}")
            except psutil.NoSuchProcess:
                print(f"Process with PID {pid} no longer exists.")
            except Exception as e:
                print(f"Error occurred while processing PID {pid}: {e}")

    def run_checks(self):
        ip_port_pairs = self.get_ips_from_netstat()
        for ip, port in ip_port_pairs:
            try:
                if self.checks_counter == self.max_checks_per_minute:
                    print("You have reached the API rate limit. Waiting 60 seconds...")
                    sleep(60)
                    self.checks_counter = 0  # Reset the counter after waiting
                self.virustotal_api([(ip, port)])
                self.checks_counter += 1
            except Exception as e:
                print(f'Error occurred while processing IP {ip}:{port}: {e}')

if __name__ == "__main__":
    api_key = ''
    netstat = NetstatOutput(api_key)
    netstat.run_checks()
