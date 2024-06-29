import argparse
import platform

class UserInterface:
    def __init__(self):
        pass

    def welcome_message(self):
        print("=== Welcome to System Security Check ===")

    def menu(self):
        print("\nMenu:")
        print("1. Check IP reputation of remote addresses we connect to.")
        print("2. Check process paths and parent processes for non-default applications.")
        print("3. Create CanaryToken")                
        print("4. Check default services")
        print("5. Analyze logs looking for adversary")
        print("6. Create File Intergrity Monitorting baseline")
        print("7. Exit")

        choice = int(input("Enter your choice (1/2/3/4/5/6/7): "))
        return choice

    def get_api_key(self):
        return input('Please enter correct API key for VirusTotal: ')

    def get_os_type(self):
        return platform.system()

    def get_os_version(self):
        return platform.release()
