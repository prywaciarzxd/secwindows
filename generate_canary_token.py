import requests
from time import sleep
import platform
import os

class CanaryTokenGenerator:
    def __init__(self) -> None:
        pass

    def get_payload(self):
        print('[?] What canary type do you want to create?')
        canary_type = input("[+] Enter ms_word, adobe_pdf, ms_excel: ")
        email = input('[+] Enter e-mail to send notification to: ')
        return {
            'type': canary_type,
            'email': email,
            'webhook_url': '',
            'fmt': '',
            'sql_server_sql_action': '',
            'azure_id_cert_file_name': '',
            'cmd_process': '',
            'clonedsite': '',
            'css_expected_referrer': '',
            'entra_expected_referrer': 'microsoftonline.com',
            'sql_server_table_name': 'TABLE1',
            'sql_server_view_name': 'VIEW1',
            'sql_server_function_name': 'FUNCTION1',
            'sql_server_trigger_name': 'TRIGGER1',
            'redirect_url': '',
            'memo': 'aaa'
        }

    def get_headers(self):
        system = platform.system()
        if system == 'Windows':
            user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
        elif system == 'Linux':
            user_agent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
        else:
            user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'

        headers = {
            'User-Agent': user_agent,
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'X-Requested-With': 'XMLHttpRequest',
            'Origin': 'https://canarytokens.org',
            'Referer': 'https://canarytokens.org/generate'
        }
        return headers

    def post_request(self):
        headers = self.get_headers()
        payload = self.get_payload()
        response = requests.post(url='https://canarytokens.org/generate', data=payload, headers=headers)

        if response.status_code == 200:
            data = response.json()
            download_url = data.get('token_url')
            if download_url:
                save_location = self.get_save_location()
                if save_location:
                    self.download_file(download_url, save_location)
            else:
                print("[-] Failed to retrieve download URL.")
        else:
            print(f"[-] Failed to generate token. Status code: {response.status_code}")

    def get_save_location(self):
        save_location = None
        if platform.system() == 'Windows':
            user_home = os.getenv('USERPROFILE')
            save_location = os.path.join(user_home, 'Downloads', 'canary_token.xlsx')
        elif platform.system() == 'Linux':
            user_home = os.path.expanduser('~')
            save_location = os.path.join(user_home, 'Documents', 'canary_token.xlsx')
        else:
            print("[-] Unsupported operating system.")
        return save_location

    def download_file(self, url, save_location):
        response = requests.get(url)
        if response.status_code == 200:
            with open(save_location, 'wb') as file:
                file.write(response.content)
            print(f"[+] File successfully downloaded to {save_location}")
        else:
            print(f"[-] Failed to download file. Status code: {response.status_code}")
        sleep(5)

kanarel = CanaryTokenGenerator()
kanarel.post_request()
