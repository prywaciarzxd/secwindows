import platform
import os
import subprocess

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
            github_password = 
            command = f'ssh-keygen -t ed25519 -C "{email}"'
            subprocess.run(command, shell=True, check=True)
            print("SSH key generated successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Error generating SSH key: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")
            
        #musi sie wykonac ta komenda z emailem ssh-keygen -t ed25519 -C "your_email@example.com"

    def display(self):
        try:
            contents = os.listdir(self.keys_dir_path)
            for file in contents:
                if file.endswith('.pub'):
                    public_key_path = os.path.join(self.keys_dir_path, file)
                    print(f"Public key ({file}):")
                    with open(public_key_path, 'r') as f:
                        key_content = f.read().strip()
                        print(key_content)
        except FileNotFoundError:
            print(f"Directory '{self.keys_dir_path}' not found.")
        except PermissionError:
            print(f"Permission denied to access '{self.keys_dir_path}'.")


    def display_existing_keys(self, command):
        if command == 'display':
            self.display()
        if command == 'display && add':
            self.display()
            self.github_public_shh_key_add()

    def github_public_shh_key_add(self):
        print("Adding public SSH key to GitHub...")
        # Tutaj wstaw kod do dodawania klucza publicznego do GitHub

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
