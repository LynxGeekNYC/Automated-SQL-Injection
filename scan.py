import subprocess
import sys
import concurrent.futures
from prettytable import PrettyTable
import smtplib
from email.mime.text import MIMEText

# Function to run Nmap to detect open ports and services
def run_nmap(target, ports="80,443", timeout=30, custom_args=""):
    print(f"[*] Running Nmap scan on {target} for ports {ports}...")
    try:
        nmap_cmd = ["nmap", "-p", ports, "--open", "--max-retries=2", "--host-timeout", f"{timeout}s"] + custom_args.split() + [target]
        nmap_result = subprocess.run(nmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        result_str = nmap_result.stdout.decode('utf-8')

        # Log the result
        log_results(f"{target}_nmap_results.txt", result_str)

        # Check if port 80 or 443 is open (indicating a web server)
        if "80/tcp open" in result_str or "443/tcp open" in result_str:
            print(f"[+] Web server detected on {target}")
            return True, result_str
        else:
            print(f"[-] No web server detected on {target}.")
            return False, result_str

    except subprocess.TimeoutExpired:
        print("[!] Nmap scan timed out.")
        return False, "[!] Nmap scan timed out."
    except Exception as e:
        print(f"[!] Error running Nmap: {str(e)}")
        return False, f"[!] Error running Nmap: {str(e)}"

# Function to run SQLMap for SQL injection vulnerability detection and dumping data
def run_sqlmap(target, dump=False, proxy=None, timeout=300, level=2, risk=1, custom_args=""):
    print(f"[*] Running SQLMap scan on {target}...")
    try:
        sqlmap_cmd = ["sqlmap", "-u", target, "--batch", "--level", str(level), "--risk", str(risk)] + custom_args.split()

        if proxy:
            sqlmap_cmd += ["--proxy", proxy]
        if dump:
            sqlmap_cmd += ["--dump"]

        sqlmap_result = subprocess.run(sqlmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        result_str = sqlmap_result.stdout.decode('utf-8')

        # Log the result
        log_results(f"{target}_sqlmap_results.txt", result_str)

        # Check for SQL injection vulnerability in the output
        if "sqlmap identified the following injection point(s)" in result_str:
            print("[+] SQL Injection vulnerability detected.")
            if dump:
                print("[*] Attempting to dump the database...")
            return True, result_str
        else:
            print("[-] No SQL Injection vulnerability detected.")
            return False, result_str

    except subprocess.TimeoutExpired:
        print("[!] SQLMap scan timed out.")
        return False, "[!] SQLMap scan timed out."
    except Exception as e:
        print(f"[!] Error running SQLMap: {str(e)}")
        return False, f"[!] Error running SQLMap: {str(e)}"

# Function to log results into a file
def log_results(filename, data):
    with open(filename, 'a') as log_file:
        log_file.write(data + '\n')

# Function to display results in a formatted table
def display_results(target, nmap_results, sqlmap_results, dump=False):
    table = PrettyTable()
    table.field_names = ["Target", "Nmap Result", "SQLMap Vulnerability", "SQL Dump Status"]
    table.add_row([target, "Web Server Detected" if nmap_results else "No Web Server", "Vulnerable" if sqlmap_results else "Not Vulnerable", "Success" if dump else "No Dump"])
    print(table)

# Function to send email notifications
def send_email_notification(to_email, scan_result):
    msg = MIMEText(scan_result)
    msg['Subject'] = 'Scan Completed'
    msg['From'] = 'your_email@example.com'
    msg['To'] = to_email

    s = smtplib.SMTP('smtp.example.com')  # You need to configure your SMTP server
    s.send_message(msg)
    s.quit()

# Main scanning function for each target
def scan_target(target, ports="80,443", proxy=None, dump=False, level=2, risk=1, nmap_args="", sqlmap_args="", email=None):
    # Run Nmap scan
    web_detected, nmap_result = run_nmap(target, ports=ports, custom_args=nmap_args)

    # Run SQLMap if a web server is detected
    if web_detected:
        vulnerable, sqlmap_result = run_sqlmap(target, dump=dump, proxy=proxy, level=level, risk=risk, custom_args=sqlmap_args)
        display_results(target, web_detected, vulnerable, dump)
        if email:
            send_email_notification(email, f"Scan completed for {target}.\n\nNmap Results:\n{nmap_result}\n\nSQLMap Results:\n{sqlmap_result}")
    else:
        print(f"[!] Skipping SQLMap for {target}, no web server detected.")

# Main function to handle multiple targets and user inputs
def main():
    targets = input("Enter target URL or IP (comma-separated for multiple targets): ").split(',')
    ports = input("Enter ports to scan (default 80,443): ") or "80,443"
    proxy = input("Enter proxy (leave blank for no proxy): ")
    email = input("Enter email for notifications (leave blank for no email): ")
    dump_choice = input("Attempt SQL dump if vulnerable? (y/n): ").lower() == 'y'
    level = input("SQLMap scan level (default 2): ") or "2"
    risk = input("SQLMap risk level (default 1): ") or "1"
    nmap_args = input("Enter custom Nmap arguments (leave blank for default): ")
    sqlmap_args = input("Enter custom SQLMap arguments (leave blank for default): ")

    # Run scans in parallel
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(scan_target, target.strip(), ports, proxy, dump_choice, int(level), int(risk), nmap_args, sqlmap_args, email) for target in targets]
        concurrent.futures.wait(futures)

if __name__ == "__main__":
    main()
