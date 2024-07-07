from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from collections import defaultdict
import os

class EventsParser:
    def __init__(self) -> None:
        self.paths = self.get_input()

    def get_input(self):
        events_path = 'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx'
        output_path = 'C:\\Users\\gigahaker\\Desktop\\logs.txt'
        #events_path = input('[+] Enter path of logs to be parsed: ')
        #output_path = input('[+] Enter path to file with parsed logs: ')
        return {'events_path': events_path, 'output_path': output_path}

    def parse_evtx_to_txt(self):
        if os.path.exists(self.paths['output_path']):
            print(f"File '{self.paths['output_path']}' already exists. Skipping parsing.")
            return
        
        with Evtx(self.paths['events_path']) as log:
            with open(self.paths['output_path'], 'w', encoding='utf-8') as output_file:
                for record in log.records():
                    xml_str = record.xml()
                    root = ET.fromstring(xml_str)
                    pretty_xml_str = ET.tostring(root, encoding='utf-8').decode('utf-8')
                    output_file.write(pretty_xml_str + "\n\n")

    def detect_bruteforce_attacks(self):
        failed_login_attempts = defaultdict(list)
        bruteforce_attacks = []

        with Evtx(self.paths['events_path']) as log:
            for record in log.records():
                xml_str = record.xml()
                root = ET.fromstring(xml_str)
                
                # Extract relevant data from the event
                event_id_elem = root.find(".//EventID")
                if event_id_elem is not None:
                    event_id = event_id_elem.text.strip()
                    if event_id == "4625":  # Failed login attempt
                        target_username_elem = root.find(".//Data[@Name='TargetUserName']")
                        if target_username_elem is not None:
                            target_username = target_username_elem.text.strip()
                            time_created_str = root.find(".//TimeCreated").attrib.get('SystemTime', '')
                            if time_created_str:
                                time_created = datetime.strptime(time_created_str, "%Y-%m-%d %H:%M:%S.%f")
                                
                                # Store failed login attempt
                                failed_login_attempts[target_username].append(time_created)

        # Analyze failed login attempts for potential bruteforce attacks
        for username, login_times in failed_login_attempts.items():
            login_times.sort()
            for i in range(len(login_times) - 4 + 1):  # Looking for 5 or more attempts within 5 minutes
                if login_times[i + 4 - 1] - login_times[i] <= timedelta(minutes=5):
                    bruteforce_attacks.append({
                        'Username': username,
                        'AttemptTimes': login_times[i:i+4]
                    })
                    break
        
        # Print or log detected bruteforce attacks
        if bruteforce_attacks:
            print("Detected bruteforce attacks:")
            for attack in bruteforce_attacks:
                print(f"Username: {attack['Username']}")
                print("Attempt times:")
                for attempt_time in attack['AttemptTimes']:
                    print(f"  - {attempt_time}")
                print()
        else:
            print("No bruteforce attacks detected.")

if __name__ == "__main__":
    events = EventsParser()
    events.parse_evtx_to_txt()  # Parse EVTX to TXT if output file doesn't exist
    events.detect_bruteforce_attacks()  # Detect bruteforce attacks
