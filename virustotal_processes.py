import os
import hashlib
import requests
import psutil
import time
from user_interface import UserInterface
import signal
import sys

class VirusTotalProcesses:
    def __init__(self, api_key):
        self.headers = {"accept": "application/json", "x-apikey": api_key}
        self.url = "https://www.virustotal.com/api/v3/"
        self.system_processes = [
            'winit.exe', 'svchost.exe', 'csrss.exe', 'lsass.exe', 'lsm.exe', 'services.exe',
            'wininit.exe', 'winlogon.exe', 'smss.exe', 'spoolsv.exe', 'System', 'Idle', 'Registry'
        ]
        self.apps_paths = [
            'C:\Program Files',
            'C:\Program Files (x86)',  # Dla aplikacji 32-bitowych na systemach 64-bitowych
            'C:\Windows',      # Dla aplikacji 32-bitowych na systemach 64-bitowych
        ]
        self.retry_wait_time = 60  # 60 seconds

        # Flag to handle interrupt signal
        self.interrupted = False

        # Dictionary to store checked processes
        self.checked_processes = {}

        # List to store malicious processes
        self.malicious_processes = []

    def get_non_system_apps(self):
        try:
            processes_list = self.get_all_processes()
            non_system_processes = []
            hash_upload_list = []
            for process in processes_list:
                pid = process['pid']
                name = process['name']
                exe_path = process['exe']

                # Skip if it's a system process or in known paths
                if exe_path and (self.is_system_process(exe_path) or self.is_in_apps_paths(exe_path)):
                    continue

                # Skip if already checked by name
                if name in self.checked_processes:
                    continue

                self.checked_processes[name] = pid

                non_system_processes.append(process)

            if non_system_processes:
                print("\nNon-system processes found:")
                for process in non_system_processes:
                    print(f"PID: {process['pid']}, Name: {process['name']}, User: {process['username']}, Path: {process['exe']}")
                    try:
                        if process['exe'] is None:
                            print(f"Skipping PID {process['pid']} because of missing path.")
                            continue

                        if process['name'] not in hash_upload_list:
                            self.upload_to_virustotal(process['exe'])
                            hash_upload_list.append(process['name'])

                    except Exception as e:
                        print(f"Error uploading to VirusTotal: {e}")

            else:
                print("\nNo non-system processes found.")

            # Save malicious processes to file
            if self.malicious_processes:
                self.save_to_file()

        except KeyboardInterrupt:
            self.interrupted = True
            print("\nProcess interrupted by user.")
        except Exception as e:
            print(f"Error occurred: {e}")

    def is_system_process(self, exe_path):
        for system_process in self.system_processes:
            if os.path.basename(exe_path).lower() == system_process.lower():
                return True
        return False

    def is_in_apps_paths(self, exe_path):
        for app_path in self.apps_paths:
            if exe_path.startswith(app_path):
                return True
        return False

    def calculate_file_hash(self, file_path):
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def upload_file(self, file_path):
        url = f"{self.url}files"
        try:
            with open(file_path, 'rb') as file:
                files = {'file': file}
                response = requests.post(url, headers=self.headers, files=files)
                if response.status_code == 429 or response.status_code == 400:
                    print(f"Received status code {response.status_code}. Retrying in {self.retry_wait_time} seconds...")
                    time.sleep(self.retry_wait_time)
                    response = requests.post(url, headers=self.headers, files=files)  # Retry the request

                response.raise_for_status()
                result = response.json()
                if response.status_code == 200:
                    return result['data']['id']
                else:
                    print(f"Error uploading file {file_path}: {response.status_code}")
                    return None
        except requests.exceptions.RequestException as e:
            print(f"Error occurred during request: {e}")
            return None
        except IOError as e:
            print(f"Error opening file {file_path}: {e}")
            return None

    def upload_hash(self, hash_value):
        url = f"{self.url}search?query={hash_value}"
        try:
            response = requests.get(url, headers=self.headers)
            if response.status_code == 429 or response.status_code == 400:
                print(f"Received status code {response.status_code}. Retrying in {self.retry_wait_time} seconds...")
                time.sleep(self.retry_wait_time)
                response = requests.get(url, headers=self.headers)  # Retry the request

            response.raise_for_status()
            result = response.json()
            if response.status_code == 200 and len(result['data']) > 0:
                malicious = result['data'][0]['attributes']['last_analysis_stats']['malicious']
            else:
                malicious = 0
            return malicious
        except requests.exceptions.RequestException as e:
            print(f"Error occurred during request: {e}")
            return 0

    def get_all_processes(self):
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'exe']):
            try:
                process_info = proc.info
                processes.append(process_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return processes

    def upload_to_virustotal(self, exe_path):
        try:
            file_hash = self.calculate_file_hash(exe_path)
            if not file_hash:
                print(f"Skipping {exe_path} due to failure in calculating hash.")
                return

            print(f"Uploading file {exe_path} to VirusTotal...")
            file_id = self.upload_file(exe_path)
            if file_id:
                print(f"File uploaded successfully. VirusTotal ID: {file_id} \n")
            else:
                print(f"Failed to upload file {exe_path} to VirusTotal. \n")
                return

            malicious_count = self.upload_hash(file_hash)
            print(f"Hash: {file_hash}, Malicious Count: {malicious_count}")

            # Save process with positive malicious count to list
            if malicious_count > 0:
                self.malicious_processes.append({
                    'pid': os.getpid(),
                    'name': os.path.basename(exe_path),
                    'user': psutil.Process(os.getpid()).username(),
                    'path': exe_path,
                    'malicious_count': malicious_count
                })

        except FileNotFoundError as e:
            print(f"Error uploading to VirusTotal: {e} \n")
        except requests.exceptions.RequestException as e:
            print(f"Error occurred during request: {e} \n")
        except Exception as e:
            print(f"Unexpected error occurred: {e} \n")

    def save_to_file(self):
        filename = 'malicious_processes.txt'
        with open(filename, 'w') as file:
            file.write("Malicious Processes:\n")
            for process in self.malicious_processes:
                file.write(f"PID: {process['pid']}, Name: {process['name']}, User: {process['user']}, Path: {process['path']}, Malicious Count: {process['malicious_count']}\n")

        print(f"\nSaved {len(self.malicious_processes)} malicious processes to {filename}.")

def main():
    try:
        user_interface = UserInterface()
        api_key = user_interface.get_api_key()
        virustotal = VirusTotalProcesses(api_key)

        # Handle interrupt signal (Ctrl+C)
        signal.signal(signal.SIGINT, signal_handler)

        virustotal.get_non_system_apps()

    except Exception as e:
        print(f"Error occurred: {e}")

def signal_handler(sig, frame):
    print("\nCtrl+C detected. Exiting...")
    sys.exit(0)

if __name__ == "__main__":
    main()
