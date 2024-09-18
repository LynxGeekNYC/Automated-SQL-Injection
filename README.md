# Automated-SQL-Injection
This is an Automated SQL Injection and Datadump python script that uses "nmap" and "sqlmap." 

# Prerequisites:
- Nmap installed (sudo apt-get install nmap)
- SQLMap installed (sudo apt-get install sqlmap or download from SQLMap)
- Python installed (>= 3.x)
- pip install prettytable

# Breakdown of Features and Enhancements:
- Custom Port Scanning: You can specify custom ports to scan with Nmap.
- Custom SQLMap Options: The user can choose the SQLMap scanning level, risk, and add custom arguments for more flexibility.
- Parallel Scanning: The script can handle multiple targets simultaneously using Python's concurrent.futures.
- Timeouts for Nmap and SQLMap: Timeouts are set for both scans to prevent them from running indefinitely.
- Proxy Support: The script supports proxy for SQLMap scans.
- Logging Results: All scan results are logged in files (nmap_results.txt and sqlmap_results.txt).
- Formatted Output: Results are displayed in a pretty table using the prettytable library.
- Email Notifications: The script sends email notifications when scans are completed, useful for long-running operations.
- Error Handling: Proper error handling and timeouts are in place to ensure the script doesn’t hang or crash.

#Was this script helpful? Please donate!

PayPal: alex@alexandermirvis.com

CashApp / Venmo: LynxGeekNYC

BitCoin: bc1q8sthd96c7chhq5kr3u80xrxs26jna9d8c0mjh7
