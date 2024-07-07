import platform
import os
import subprocess
from time import sleep


class SshKeyGenerator:
    def __init__(self):
        self.os_type = self.get_os()
        self.username = os.getlogin()
        self.keys_dir_path = self.get_path(self.os_type)
        self.are_keys = self.check_directory_keys()
    
    def get_os(self):
        return platform.system()
    
    def get_path(self, os_type):
        if os_type == 'Windows':
            default_path = f'C:\\Users\\{self.username}\\.ssh\\'
        elif os_type == 'Linux':
            default_path = f'/home/{self.username}/.ssh/'
        else:
            print(f"Your {os_type} is not supported!")
            exit(1)
        return default_path


    def create_ssh_key(self):
        try:
            email = input("please enter your email: ")
            if self.os_type == 'Windows':
                command = f'ssh-keygen.exe -t ed25519 -C {email}'
            elif self.os_type == 'Linux':
                command = f'ssh-keygen -t ed25519 -C "{email}"'
            subprocess.run(command, shell=True, check=True)
            print("SSH key generated successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Error generating SSH key: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")
            
    def print_public_key(self, keys_dir_path):
        contents = os.listdir(keys_dir_path)
        for file in contents:
            if file.endswith('.pub'):
                public_key_path = os.path.join(keys_dir_path, file)
                print(f"Public key ({file}):")
                with open(public_key_path, 'r') as f:
                    key_content = f.read().strip()
                    print(key_content)

    def get_ssh_dir(self):
        print(f'[+] Checking default path ssh key diretory .....   \n')
        if self.os_type == 'Windows':
            ssh_default_dir = f'C:\\Users\\{self.username}\\.ssh'
        elif self.os_type == 'Linux':
            ssh_default_dir = f'/home/{os.getlogin()}/.ssh/'
        return ssh_default_dir

    def display(self):
        
        keys_dir_path = self.get_ssh_dir()
        try:
            self.print_public_key(keys_dir_path)
        except FileNotFoundError:
            print(f"Directory '{self.keys_dir_path}' not found.")
        except PermissionError:
            print(f"Permission denied to access '{self.keys_dir_path}'.")


    def display_existing_keys(self, command):
        if command == 'display':
            self.display()
        if command == 'display && add':
            self.github_public_shh_key_add()
            self.display()
            
    def github_public_shh_key_add(self):
        print("Adding public SSH key to GitHub... \n")
        print("Go to: https://github.com/settings/ssh/new and paste ur public key! \n")
        #print(f'Public key to copy: {subprocess.run(['cat', 'example.txt'], capture_output=True, text=True)}')
    def check_directory_keys(self):
        try:
            contents = os.listdir(self.keys_dir_path)
            if 'id_ed25519' in contents or 'id_ed25519.pub' in contents:
                print(f"[+] Found keys: {'id_ed25519' in contents}, {'id_ed25519.pub' in contents}")
                choice = input("Do you want to continue generating a new SSH key? (y/n): ")
                if choice.lower() in ['y', 'yes']:
                    self.create_ssh_key()
                else:
                    choice2 = input("Do you want to display your public key and add it to GitHub? (display/display && add/n): ")
                    if choice2.lower() == 'display && add':
                        self.display_existing_keys('display && add')
                        self.github_public_shh_key_add()
                    elif choice2.lower() == 'display':
                        self.display_existing_keys('display')
                    else:
                        print("Exiting...")
                        exit(1)
            else:
                print("No SSH keys found.")
        except FileNotFoundError:
            print(f"Directory '{self.keys_dir_path}' not found.")
        except PermissionError:
            print(f"Permission denied to access '{self.keys_dir_path}'.")

if __name__ == "__main__":
    ssh = SshKeyGenerator()
    ssh.check_directory_keys()