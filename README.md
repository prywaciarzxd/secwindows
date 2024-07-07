# System Security Analysis Tool

Welcome to the System Security Analysis Tool repository!

This tool is designed to help you analyze and enhance the security of your operating system, compatible with both Linux and Windows. It leverages the VirusTotal API to verify hashes and IP addresses, generates CanaryTokens (traps for hackers), and creates SSH keys. Additionally, it allows you to perform a baseline analysis of applications to detect potential adversaries.

## Main Features:
- **Analyze Active Network Connections:** Use the 'netstat' command to analyze active network connections.
- **VirusTotal Integration:** Verify the reputation of IP addresses and hashes using the VirusTotal API.
- **Generate CanaryTokens:** Create traps to detect unauthorized access.
- **SSH Key Management:** Generate or verify the existence of SSH keys for GitHub.
- **Baseline Analysis:** Establish a baseline of applications to identify suspicious activity.
- **Check Default Services:** Analyze and ensure the security of default services.
- **Log Analysis:** Look for signs of adversary activity in system logs.
- **File Integrity Monitoring:** Create a baseline for file integrity monitoring.

## New Feature:
- **IP Reputation Check:** Added functionality for users to check individual IP addresses by passing them as command-line arguments using the `--ips` flag.

## Requirements:
- Python 3.x
- `requests` package
- VirusTotal account and API key (for full functionality)
- Compatible with Linux and Windows

## How to Use:
1. **Run the Main Script:**
   ```bash
   python main.py

## Project Structure
- generate_canary_token.py - Script to create a CanaryToken.
- generate_github_ssh_key.py - Script to create or check for a GitHub SSH key.
- main.py - Entry point for the application.
- netstat_output.py - Handles netstat command output processing.
- README.md - Project documentation.
- user_interface.py - Handles user interaction and menu options.
- virustotal_processes.py - Interacts with the VirusTotal API.

