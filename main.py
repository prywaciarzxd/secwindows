import argparse
from user_interface import UserInterface
from netstat_output import NetstatOutput
from virustotal_processes import VirusTotalProcesses
import signal 
import sys

def main():
    try:
        user_interface = UserInterface()
        user_choice = user_interface.menu()

        if user_choice == 1:
            api_key = user_interface.get_api_key()
            netstat = NetstatOutput(api_key)
            signal.signal(signal.SIGINT, signal_handler)
            netstat.run_checks()
        elif user_choice == 2:
            api_key = user_interface.get_api_key()
            virustotal = VirusTotalProcesses(api_key)
            signal.signal(signal.SIGINT, signal_handler)
            virustotal.get_non_system_apps()
        elif user_choice == 3:
            # Placeholder for future functionality - kanarek
            pass
        elif user_choice == 4:
            # Placeholder for future functionality - security events
            pass
        elif user_choice == 5:
            pass #SECURITY WINDOWS LOGS ANALYZER
        elif user_choice == 6:
            pass #FIM
        elif user_choice == 7:
            pass
            #ssh function
        elif user_choice == 8:
            print('Exiting the tool.')
            return
        else:
            print('Invalid choice. Please enter a valid option.')

    except Exception as e:
        print(f"Error occurred: {e}")

def signal_handler(sig, frame):
    print("\nCtrl+C detected. Exiting...")
    sys.exit(0)

if __name__ == "__main__":
    main()
