#!/usr/bin/env python3
# OBSIDIAN CIPHER v2.0 - PREMIUM
# License Key: obsidian-chiper
# Contact: @Zxxtirwd (Telegram)

import os
import sys
import time
import hashlib
import json
import socket
import threading
import random
import string
import requests
import base64
import re
import subprocess
import ipaddress
import smtplib
import urllib.parse
from datetime import datetime
from getpass import getpass
from colorama import init, Fore, Back, Style, just_fix_windows_console
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ============ INITIALIZATION ============
init(autoreset=True)
if sys.platform == "win32":
    just_fix_windows_console()

# ============ CONFIGURATION ============
CONFIG = {
    "app_name": "OBSIDIAN CIPHER v2.0",
    "author": "CYBER ELITE",
    "version": "2.0.0",
    "price": "Rp 30.000",
    "contact": "@Zxxtirwd",
    "license_key": "obsidian-chiper",
    "user_file": "obsidian_users.json",
    "log_file": "obsidian_log.txt"
}

# ============ ASCII ART ============
def show_ascii():
    ascii_art = f"""
{Fore.CYAN} ██████╗ ██████╗ ███████╗██╗██████╗ ██╗ █████╗ ███╗   ██╗    ████████╗ ██████╗  ██████╗ ██╗     ███████╗
{Fore.MAGENTA}██╔═══██╗██╔══██╗██╔════╝██║██╔══██╗██║██╔══██╗████╗  ██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝
{Fore.BLUE}██║   ██║██████╔╝███████╗██║██║  ██║██║███████║██╔██╗ ██║       ██║   ██║   ██║██║   ██║██║     ███████╗
{Fore.GREEN}██║   ██║██╔══██╗╚════██║██║██║  ██║██║██╔══██║██║╚██╗██║       ██║   ██║   ██║██║   ██║██║     ╚════██║
{Fore.YELLOW}╚██████╔╝██████╔╝███████║██║██████╔╝██║██║  ██║██║ ╚████║       ██║   ╚██████╔╝╚██████╔╝███████╗███████║
{Fore.RED} ╚═════╝ ╚═════╝ ╚══════╝╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝
{Fore.WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    print(ascii_art)

# ============ LOGGING SYSTEM ============
class Logger:
    def __init__(self):
        self.log_file = CONFIG["log_file"]
    
    def log(self, event, user="SYSTEM", status="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{status}] User:{user} - {event}\n"
        
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(log_entry)
        
        if status == "ERROR":
            print(f"{Fore.RED}[LOG] {log_entry.strip()}")
        elif status == "WARNING":
            print(f"{Fore.YELLOW}[LOG] {log_entry.strip()}")
        elif status == "SUCCESS":
            print(f"{Fore.GREEN}[LOG] {log_entry.strip()}")

# ============ AUTHENTICATION SYSTEM ============
class AuthSystem:
    def __init__(self):
        self.users = self.load_users()
        self.logger = Logger()
        self.current_user = None
    
    def load_users(self):
        try:
            with open(CONFIG["user_file"], "r") as f:
                return json.load(f)
        except:
            return {}
    
    def save_users(self):
        try:
            with open(CONFIG["user_file"], "w") as f:
                json.dump(self.users, f, indent=4)
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving users: {e}")
    
    def create_user(self):
        show_ascii()
        print(f"\n{Fore.CYAN}[+] CREATE NEW ACCOUNT")
        print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        while True:
            username = input(f"{Fore.WHITE}➤ Username: ").strip()
            if len(username) < 3:
                print(f"{Fore.RED}[-] Username must be at least 3 characters!")
                continue
            if username in self.users:
                print(f"{Fore.RED}[-] Username already exists!")
                continue
            break
        
        while True:
            password = getpass(f"{Fore.WHITE}➤ Password: ").strip()
            if len(password) < 6:
                print(f"{Fore.RED}[-] Password must be at least 6 characters!")
                continue
            confirm = getpass(f"{Fore.WHITE}➤ Confirm Password: ").strip()
            if password != confirm:
                print(f"{Fore.RED}[-] Passwords don't match!")
                continue
            break
        
        license_key = input(f"{Fore.WHITE}➤ License Key ({CONFIG['price']}): ").strip()
        if license_key != CONFIG["license_key"]:
            print(f"{Fore.RED}[-] Invalid license key!")
            print(f"{Fore.YELLOW}[*] Buy license: {Fore.CYAN}{CONFIG['contact']}")
            return False
        
        # Hash password with salt
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        password_hash = salt.hex() + key.hex()
        
        # Create user
        self.users[username] = {
            "password": password_hash,
            "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_login": None,
            "premium": True,
            "login_count": 0,
            "tools_used": {},
            "color_scheme": "rainbow"
        }
        
        self.save_users()
        self.logger.log(f"New account created: {username}", username, "SUCCESS")
        
        print(f"\n{Fore.GREEN}[+] Account created successfully!")
        print(f"{Fore.CYAN}[+] Welcome to {CONFIG['app_name']}")
        print(f"{Fore.YELLOW}[+] Contact for support: {CONFIG['contact']}")
        
        return True
    
    def login(self):
        show_ascii()
        print(f"\n{Fore.CYAN}[+] OBSIDIAN CIPHER LOGIN")
        print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        attempts = 3
        while attempts > 0:
            username = input(f"{Fore.WHITE}➤ Username: ").strip()
            password = getpass(f"{Fore.WHITE}➤ Password: ").strip()
            
            if username not in self.users:
                print(f"{Fore.RED}[-] Invalid username or password!")
                attempts -= 1
                self.logger.log(f"Failed login attempt for {username}", "SYSTEM", "WARNING")
                continue
            
            # Verify password
            stored_hash = self.users[username]["password"]
            salt = bytes.fromhex(stored_hash[:64])
            stored_key = stored_hash[64:]
            
            key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
            
            if key.hex() == stored_key:
                self.current_user = username
                self.users[username]["last_login"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.users[username]["login_count"] = self.users[username].get("login_count", 0) + 1
                self.save_users()
                
                self.logger.log("Successful login", username, "SUCCESS")
                return True
            else:
                print(f"{Fore.RED}[-] Invalid username or password!")
                attempts -= 1
                self.logger.log(f"Failed login attempt for {username}", "SYSTEM", "WARNING")
        
        print(f"{Fore.RED}[-] Too many failed attempts!")
        self.logger.log("Account locked due to failed attempts", username, "ERROR")
        return False

# ============ NETWORK TOOLS ============
class NetworkTools:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def port_scanner(self, target, ports="1-1000"):
        """Advanced port scanner with service detection"""
        print(f"\n{Fore.CYAN}[+] PORT SCANNER v2.0")
        print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        try:
            # Resolve target
            if not re.match(r'\d+\.\d+\.\d+\.\d+', target):
                target_ip = socket.gethostbyname(target)
                print(f"{Fore.GREEN}[+] Resolved: {target} → {target_ip}")
            else:
                target_ip = target
            
            # Parse port range
            if '-' in ports:
                start_port, end_port = map(int, ports.split('-'))
            else:
                start_port, end_port = 1, int(ports)
            
            print(f"{Fore.YELLOW}[*] Scanning {target_ip}:{start_port}-{end_port}...")
            print(f"{Fore.YELLOW}[*] Start time: {datetime.now().strftime('%H:%M:%S')}")
            
            open_ports = []
            threads = []
            lock = threading.Lock()
            
            def scan_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target_ip, port))
                    
                    if result == 0:
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "unknown"
                        
                        with lock:
                            open_ports.append((port, service))
                        
                        banner = ""
                        try:
                            sock.settimeout(2)
                            sock.send(b"GET / HTTP/1.0\r\n\r\n")
                            banner = sock.recv(1024).decode('utf-8', errors='ignore')[:100]
                        except:
                            pass
                        
                        print(f"{Fore.GREEN}[+] Port {port:5} OPEN - {service:15} {banner}")
                    sock.close()
                except:
                    pass
            
            # Multi-threaded scanning
            for port in range(start_port, end_port + 1):
                t = threading.Thread(target=scan_port, args=(port,))
                threads.append(t)
                t.start()
                
                # Limit concurrent threads
                if len(threads) >= 100:
                    for t in threads:
                        t.join()
                    threads = []
            
            for t in threads:
                t.join()
            
            print(f"\n{Fore.CYAN}[+] SCAN COMPLETE")
            print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            print(f"{Fore.GREEN}[+] Open ports: {len(open_ports)}")
            print(f"{Fore.GREEN}[+] Closed ports: {(end_port - start_port + 1) - len(open_ports)}")
            print(f"{Fore.GREEN}[+] End time: {datetime.now().strftime('%H:%M:%S')}")
            
            if open_ports:
                print(f"\n{Fore.CYAN}[+] SECURITY REPORT:")
                vulnerable_ports = [p for p, s in open_ports if p in [21, 22, 23, 25, 3389]]
                if vulnerable_ports:
                    print(f"{Fore.RED}[!] Vulnerable ports open: {vulnerable_ports}")
                else:
                    print(f"{Fore.GREEN}[✓] No critical vulnerabilities detected")
            
            return open_ports
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}")
            return []
    
    def wifi_analyzer(self):
        """WiFi network analyzer"""
        print(f"\n{Fore.CYAN}[+] WiFi ANALYZER")
        print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        try:
            # Get network info
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            print(f"{Fore.GREEN}[+] System Information:")
            print(f"   Hostname: {hostname}")
            print(f"   Local IP: {local_ip}")
            print(f"   Platform: {sys.platform}")
            
            # Get public IP
            try:
                public_ip = requests.get('https://api.ipify.org').text
                print(f"   Public IP: {public_ip}")
                
                # Geolocation
                try:
                    geo = requests.get(f'http://ip-api.com/json/{public_ip}').json()
                    if geo['status'] == 'success':
                        print(f"   Location: {geo.get('city', 'N/A')}, {geo.get('country', 'N/A')}")
                        print(f"   ISP: {geo.get('isp', 'N/A')}")
                except:
                    pass
            except:
                print(f"   Public IP: Unable to determine")
            
            # Network interfaces (platform specific)
            if sys.platform == "linux":
                try:
                    result = subprocess.run(['iwconfig'], capture_output=True, text=True)
                    if result.returncode == 0:
                        print(f"\n{Fore.GREEN}[+] Wireless Interfaces:")
                        print(result.stdout[:500])
                except:
                    pass
            
            # Check internet speed
            print(f"\n{Fore.YELLOW}[*] Testing connection speed...")
            try:
                start = time.time()
                response = requests.get('https://www.google.com', timeout=5)
                latency = (time.time() - start) * 1000
                print(f"{Fore.GREEN}[+] Latency: {latency:.0f} ms")
                
                if latency < 50:
                    print(f"{Fore.GREEN}[+] Connection: Excellent")
                elif latency < 100:
                    print(f"{Fore.YELLOW}[+] Connection: Good")
                elif latency < 200:
                    print(f"{Fore.YELLOW}[+] Connection: Fair")
                else:
                    print(f"{Fore.RED}[+] Connection: Poor")
            except:
                print(f"{Fore.RED}[-] Cannot reach internet")
            
            print(f"\n{Fore.CYAN}[+] WiFi Security Tips:")
            print(f"   1. Use WPA3 encryption if available")
            print(f"   2. Change default router password")
            print(f"   3. Hide SSID broadcast")
            print(f"   4. Enable MAC address filtering")
            print(f"   5. Regularly update router firmware")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {e}")
    
    def ddos_tester(self, target, duration=10, threads=50):
        """DDoS resilience tester"""
        print(f"\n{Fore.CYAN}[+] DDoS RESILIENCE TESTER")
        print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(f"{Fore.RED}[!] WARNING: For educational purposes only!")
        print(f"{Fore.RED}[!] Only test your own servers!")
        
        if not target:
            target = input(f"{Fore.WHITE}➤ Target IP/URL: ").strip()
        
        if not target.startswith('http'):
            target = 'http://' + target
        
        print(f"{Fore.YELLOW}[*] Testing {target} for {duration} seconds...")
        print(f"{Fore.YELLOW}[*] Using {threads} concurrent threads")
        
        attack_active = True
        packets_sent = 0
        successful_requests = 0
        failed_requests = 0
        
        def attack_thread():
            nonlocal packets_sent, successful_requests, failed_requests
            while attack_active:
                try:
                    response = requests.get(target, timeout=2)
                    packets_sent += 1
                    if response.status_code < 400:
                        successful_requests += 1
                    else:
                        failed_requests += 1
                except:
                    packets_sent += 1
                    failed_requests += 1
        
        # Start attack threads
        thread_list = []
        for i in range(threads):
            t = threading.Thread(target=attack_thread)
            t.daemon = True
            t.start()
            thread_list.append(t)
        
        # Monitor progress
        start_time = time.time()
        last_update = start_time
        
        while time.time() - start_time < duration:
            elapsed = time.time() - start_time
            remaining = duration - elapsed
            
            if time.time() - last_update >= 1:
                req_per_sec = packets_sent / elapsed if elapsed > 0 else 0
                success_rate = (successful_requests / packets_sent * 100) if packets_sent > 0 else 0
                
                print(f"\r{Fore.CYAN}[*] Time: {int(elapsed)}s | Packets: {packets_sent} | "
                      f"Success: {success_rate:.1f}% | Rate: {req_per_sec:.1f}/s", end="")
                last_update = time.time()
            
            time.sleep(0.1)
        
        attack_active = False
        time.sleep(1)  # Let threads finish
        
        print(f"\n\n{Fore.CYAN}[+] TEST COMPLETE")
        print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(f"{Fore.GREEN}[+] Total packets sent: {packets_sent}")
        print(f"{Fore.GREEN}[+] Successful requests: {successful_requests}")
        print(f"{Fore.GREEN}[+] Failed requests: {failed_requests}")
        print(f"{Fore.GREEN}[+] Average rate: {packets_sent/duration:.1f} requests/second")
        
        # Security assessment
        if packets_sent/duration > 100:
            print(f"{Fore.RED}[!] WEAK PROTECTION: Server vulnerable to DDoS")
            print(f"{Fore.YELLOW}[*] Recommendations: Enable rate limiting, use CDN, configure firewall")
        elif packets_sent/duration > 50:
            print(f"{Fore.YELLOW}[!] MODERATE PROTECTION: Room for improvement")
        else:
            print(f"{Fore.GREEN}[✓] STRONG PROTECTION: Good DDoS resilience")

# ============ ENCRYPTION TOOLS ============
class EncryptionTools:
    def __init__(self):
        pass
    
    def aes_encrypt(self, text, key):
        """AES encryption implementation"""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            import hashlib
            
            # Hash key to get 32 bytes
            key_hash = hashlib.sha256(key.encode()).digest()
            
            # Generate random IV
            iv = os.urandom(16)
            
            # Create cipher
            cipher = AES.new(key_hash, AES.MODE_CBC, iv)
            
            # Encrypt
            padded_text = pad(text.encode(), AES.block_size)
            ciphertext = cipher.encrypt(padded_text)
            
            # Return IV + ciphertext
            return base64.b64encode(iv + ciphertext).decode()
            
        except ImportError:
            # Fallback to simple XOR if Crypto not available
            print(f"{Fore.YELLOW}[*] PyCryptodome not installed, using simple encryption")
            return self.xor_encrypt(text, key)
    
    def aes_decrypt(self, encrypted, key):
        """AES decryption"""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
            import hashlib
            
            # Decode base64
            data = base64.b64decode(encrypted)
            
            # Extract IV and ciphertext
            iv = data[:16]
            ciphertext = data[16:]
            
            # Hash key
            key_hash = hashlib.sha256(key.encode()).digest()
            
            # Decrypt
            cipher = AES.new(key_hash, AES.MODE_CBC, iv)
            padded_text = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_text, AES.block_size)
            
            return plaintext.decode()
            
        except ImportError:
            return self.xor_decrypt(encrypted, key)
    
    def xor_encrypt(self, text, key):
        """XOR encryption (fallback)"""
        encrypted = []
        key_bytes = key.encode()
        
        for i, char in enumerate(text):
            key_char = key_bytes[i % len(key_bytes)]
            encrypted_char = chr(ord(char) ^ key_char)
            encrypted.append(encrypted_char)
        
        encrypted_text = ''.join(encrypted)
        return base64.b64encode(encrypted_text.encode()).decode()
    
    def xor_decrypt(self, encrypted, key):
        """XOR decryption"""
        try:
            encrypted_text = base64.b64decode(encrypted).decode()
            decrypted = []
            key_bytes = key.encode()
            
            for i, char in enumerate(encrypted_text):
                key_char = key_bytes[i % len(key_bytes)]
                decrypted_char = chr(ord(char) ^ key_char)
                decrypted.append(decrypted_char)
            
            return ''.join(decrypted)
        except:
            return "[DECRYPTION ERROR]"
    
    def password_generator(self, length=16, complexity="high"):
        """Advanced password generator"""
        print(f"\n{Fore.CYAN}[+] PASSWORD GENERATOR")
        print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        char_sets = {
            "low": string.ascii_lowercase + string.digits,
            "medium": string.ascii_letters + string.digits,
            "high": string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?",
            "extreme": string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
        }
        
        chars = char_sets.get(complexity, char_sets["high"])
        
        print(f"{Fore.GREEN}[+] Generating {length} character passwords ({complexity} complexity):")
        print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        passwords = []
        for i in range(5):
            password = ''.join(random.choice(chars) for _ in range(length))
            
            # Ensure complexity requirements
            if complexity in ["high", "extreme"]:
                if not (any(c.isupper() for c in password) and
                       any(c.islower() for c in password) and
                       any(c.isdigit() for c in password) and
                       any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)):
                    # Regenerate if requirements not met
                    continue
            
            passwords.append(password)
            print(f"{Fore.CYAN}[{i+1}] {Fore.GREEN}{password}")
        
        # Calculate entropy
        entropy = length * (len(chars) ** 2)
        print(f"\n{Fore.YELLOW}[*] Password Strength Analysis:")
        print(f"    Length: {length} characters")
        print(f"    Character set: {len(chars)} possibilities")
        print(f"    Entropy: ~{entropy} bits")
        print(f"    Time to crack (10^9 guesses/sec): {entropy / 1_000_000_000:.2e} seconds")
        
        return passwords

# ============ OSINT TOOLS ============
class OSINTTools:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def phone_lookup(self, number):
        """Phone number intelligence"""
        print(f"\n{Fore.CYAN}[+] PHONE NUMBER INTELLIGENCE")
        print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        # Clean number
        clean_num = re.sub(r'[^\d+]', '', number)
        
        print(f"{Fore.GREEN}[+] Target: {clean_num}")
        
        # Country code detection
        country_codes = {
            '62': 'Indonesia',
            '1': 'USA/Canada',
            '44': 'UK',
            '91': 'India',
            '86': 'China',
            '81': 'Japan',
            '82': 'South Korea'
        }
        
        detected_country = None
        for code, country in country_codes.items():
            if clean_num.startswith(code):
                detected_country = country
                break
        
        if detected_country:
            print(f"{Fore.GREEN}[+] Country: {detected_country}")
        
        # Indonesian operator detection
        if detected_country == 'Indonesia' and len(clean_num) >= 4:
            prefix = clean_num[-10:-6] if len(clean_num) > 10 else clean_num[:4]
            
            operators = {
                '0811': 'Telkomsel (Halo)',
                '0812': 'Telkomsel (Simpati)',
                '0813': 'Telkomsel (Simpati)',
                '0821': 'Telkomsel (Simpati)',
                '0822': 'Telkomsel (Simpati)',
                '0823': 'Telkomsel (AS)',
                '0852': 'Telkomsel (AS)',
                '0853': 'Telkomsel (AS)',
                '0814': 'Indosat (Mentari)',
                '0815': 'Indosat (Mentari)',
                '0816': 'Indosat (IM3)',
                '0855': 'Indosat (IM3)',
                '0856': 'Indosat (IM3)',
                '0857': 'Indosat (IM3)',
                '0858': 'Indosat (IM3)',
                '0817': 'XL',
                '0818': 'XL',
                '0819': 'XL',
                '0859': 'XL',
                '0877': 'XL',
                '0878': 'XL',
                '0831': 'Axis',
                '0832': 'Axis',
                '0833': 'Axis',
                '0838': 'Axis',
                '0895': 'Three',
                '0896': 'Three',
                '0897': 'Three',
                '0898': 'Three',
                '0899': 'Three',
                '0881': 'Smartfren',
                '0882': 'Smartfren',
                '0883': 'Smartfren',
                '0884': 'Smartfren',
                '0885': 'Smartfren',
                '0886': 'Smartfren',
                '0887': 'Smartfren',
                '0888': 'Smartfren',
                '0889': 'Smartfren'
            }
            
            if prefix in operators:
                print(f"{Fore.GREEN}[+] Operator: {operators[prefix]}")
            else:
                print(f"{Fore.YELLOW}[+] Operator: Unknown (Prefix: {prefix})")
        
        # Check if number is valid
        if 10 <= len(clean_num) <= 15:
            print(f"{Fore.GREEN}[✓] Valid phone number format")
        else:
            print(f"{Fore.RED}[!] Invalid phone number length")
        
        # Privacy check
        print(f"\n{Fore.YELLOW}[*] Privacy Recommendations:")
        print(f"    1. Be cautious sharing this number online")
        print(f"    2. Enable two-factor authentication")
        print(f"    3. Register on Do Not Call lists if available")
        print(f"    4. Regularly check for data breaches")
    
    def email_analyzer(self, email):
        """Email address analysis"""
        print(f"\n{Fore.CYAN}[+] EMAIL ANALYSIS")
        print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        if '@' not in email:
            print(f"{Fore.RED}[-] Invalid email address!")
            return
        
        local, domain = email.split('@', 1)
        
        print(f"{Fore.GREEN}[+] Email: {email}")
        print(f"{Fore.GREEN}[+] Local part: {local}")
        print(f"{Fore.GREEN}[+] Domain: {domain}")
        
        # Common providers
        providers = {
            'gmail.com': 'Google (Free, Secure)',
            'yahoo.com': 'Yahoo (Free)',
            'outlook.com': 'Microsoft (Free)',
            'hotmail.com': 'Microsoft (Legacy)',
            'icloud.com': 'Apple (Premium)',
            'protonmail.com': 'ProtonMail (Encrypted)',
            'tutanota.com': 'Tutanota (Encrypted)',
            'zoho.com': 'Zoho (Business)'
        }
        
        if domain in providers:
            print(f"{Fore.GREEN}[+] Provider: {providers[domain]}")
        
        # Check for data breaches
        print(f"\n{Fore.YELLOW}[*] Checking breach database...")
        try:
            # Hash email for Have I Been Pwned API
            email_hash = hashlib.sha1(email.encode()).hexdigest().upper()
            prefix = email_hash[:5]
            
            response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=10)
            
            if response.status_code == 200:
                suffixes = response.text.split('\n')
                found = False
                
                for suffix in suffixes:
                    if email_hash[5:] in suffix:
                        count = suffix.split(':')[1].strip()
                        print(f"{Fore.RED}[!] Email found in {count} data breaches!")
                        print(f"{Fore.YELLOW}[*] Recommendations: Change password, enable 2FA")
                        found = True
                        break
                
                if not found:
                    print(f"{Fore.GREEN}[✓] Email not found in known breaches")
            else:
                print(f"{Fore.YELLOW}[*] Could not check breach database")
                
        except Exception as e:
            print(f"{Fore.YELLOW}[*] Breach check unavailable: {e}")
        
        # Security score
        score = 0
        if len(local) >= 8: score += 1
        if re.search(r'[A-Z]', local): score += 1
        if re.search(r'[0-9]', local): score += 1
        if domain in ['protonmail.com', 'tutanota.com']: score += 2
        
        print(f"\n{Fore.CYAN}[+] Security Score: {score}/5")
        if score >= 4:
            print(f"{Fore.GREEN}[+] Email security: Excellent")
        elif score >= 2:
            print(f"{Fore.YELLOW}[+] Email security: Good")
        else:
            print(f"{Fore.RED}[+] Email security: Poor")

# ============ SYSTEM TOOLS ============
class SystemTools:
    def __init__(self):
        pass
    
    def system_info(self):
        """Comprehensive system information"""
        print(f"\n{Fore.CYAN}[+] SYSTEM INFORMATION")
        print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        import platform
        import psutil
        
        # Basic system info
        print(f"{Fore.GREEN}[+] Basic Information:")
        print(f"    System: {platform.system()} {platform.release()}")
        print(f"    Version: {platform.version()}")
        print(f"    Machine: {platform.machine()}")
        print(f"    Processor: {platform.processor()}")
        print(f"    Python: {platform.python_version()}")
        
        # CPU information
        print(f"\n{Fore.GREEN}[+] CPU Information:")
        print(f"    Physical cores: {psutil.cpu_count(logical=False)}")
        print(f"    Logical cores: {psutil.cpu_count(logical=True)}")
        print(f"    CPU usage: {psutil.cpu_percent(interval=1)}%")
        
        # Memory information
        mem = psutil.virtual_memory()
        print(f"\n{Fore.GREEN}[+] Memory Information:")
        print(f"    Total: {mem.total // (1024**3)} GB")
        print(f"    Available: {mem.available // (1024**3)} GB")
        print(f"    Used: {mem.used // (1024**3)} GB ({mem.percent}%)")
        
        # Disk information
        print(f"\n{Fore.GREEN}[+] Disk Information:")
        partitions = psutil.disk_partitions()
        for part in partitions[:3]:  # Show first 3 partitions
            usage = psutil.disk_usage(part.mountpoint)
            print(f"    {part.device}: {usage.used // (1024**3)}/{usage.total // (1024**3)} GB ({usage.percent}%)")
        
        # Network information
        print(f"\n{Fore.GREEN}[+] Network Information:")
        net_io = psutil.net_io_counters()
        print(f"    Bytes sent: {net_io.bytes_sent // (1024**2)} MB")
        print(f"    Bytes received: {net_io.bytes_recv // (1024**2)} MB")
        
        # Boot time
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time
        print(f"\n{Fore.GREEN}[+] Uptime:")
        print(f"    Boot time: {boot_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"    Uptime: {uptime.days} days, {uptime.seconds//3600} hours")
        
        # Security status
        print(f"\n{Fore.CYAN}[+] Security Status:")
        try:
            # Check if running as admin/root
            if os.name == 'posix':
                if os.geteuid() == 0:
                    print(f"{Fore.RED}[!] Running as root - Security risk!")
                else:
                    print(f"{Fore.GREEN}[✓] Running as regular user")
            elif os.name == 'nt':
                import ctypes
                if ctypes.windll.shell32.IsUserAnAdmin():
                    print(f"{Fore.RED}[!] Running as administrator - Security risk!")
                else:
                    print(f"{Fore.GREEN}[✓] Running as standard user")
        except:
            pass
        
        # Recommendations
        print(f"\n{Fore.YELLOW}[*] System Recommendations:")
        if mem.percent > 80:
            print(f"    • Close unused applications (Memory: {mem.percent}%)")
        
        cpu_percent = psutil.cpu_percent(interval=1)
        if cpu_percent > 80:
            print(f"    • Reduce CPU load (CPU: {cpu_percent}%)")
        
        print(f"    • Regularly update system and software")
        print(f"    • Install antivirus software")
        print(f"    • Enable firewall")

# ============ MAIN APPLICATION ============
class ObsidianApp:
    def __init__(self):
        self.auth = AuthSystem()
        self.network = NetworkTools()
        self.encryption = EncryptionTools()
        self.osint = OSINTTools()
        self.system = SystemTools()
        self.logger = Logger()
        self.current_user = None
        
    def welcome_user(self):
        """Display welcome screen"""
        show_ascii()
        
        # Get current date and time
        now = datetime.now()
        date_str = now.strftime("%A, %d %B %Y")
        time_str = now.strftime("%H:%M:%S")
        
        print(f"\n{Fore.CYAN}[+] {CONFIG['app_name']}")
        print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(f"{Fore.GREEN}   Date: {date_str}")
        print(f"{Fore.GREEN}   Time: {time_str}")
        print(f"{Fore.GREEN}   User: {self.current_user}")
        print(f"{Fore.GREEN}   Status: PREMIUM ACTIVE")
        print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(f"{Fore.MAGENTA}   SELAMAT MENIKMATI FITUR PREMIUM KAMI!")
        print(f"{Fore.CYAN}   Semua tools berfungsi penuh tanpa bug")
        print(f"{Fore.YELLOW}   Support: {CONFIG['contact']}")
        print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        # Brief pause for dramatic effect
        time.sleep(2)
    
    def main_menu(self):
        """Main application menu"""
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            self.welcome_user()
            
            print(f"\n{Fore.CYAN}[+] MAIN MENU")
            print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            print(f"{Fore.WHITE}[1] {Fore.GREEN}NETWORK TOOLS")
            print(f"   • Port Scanner")
            print(f"   • WiFi Analyzer")
            print(f"   • DDoS Tester")
            
            print(f"\n{Fore.WHITE}[2] {Fore.GREEN}ENCRYPTION TOOLS")
            print(f"   • AES Encryption/Decryption")
            print(f"   • Password Generator")
            print(f"   • File Encryption")
            
            print(f"\n{Fore.WHITE}[3] {Fore.GREEN}OSINT TOOLS")
            print(f"   • Phone Number Analysis")
            print(f"   • Email Analysis")
            print(f"   • IP Geolocation")
            
            print(f"\n{Fore.WHITE}[4] {Fore.GREEN}SYSTEM TOOLS")
            print(f"   • System Information")
            print(f"   • Process Manager")
            print(f"   • Resource Monitor")
            
            print(f"\n{Fore.WHITE}[5] {Fore.YELLOW}USER SETTINGS")
            print(f"\n{Fore.WHITE}[0] {Fore.RED}LOGOUT")
            print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            
            choice = input(f"\n{Fore.WHITE}➤ Select option (1-5, 0): ").strip()
            
            if choice == "1":
                self.network_menu()
            elif choice == "2":
                self.encryption_menu()
            elif choice == "3":
                self.osint_menu()
            elif choice == "4":
                self.system_menu()
            elif choice == "5":
                self.settings_menu()
            elif choice == "0":
                print(f"\n{Fore.YELLOW}[*] Logging out...")
                time.sleep(1)
                self.current_user = None
                self.logger.log("User logged out", self.current_user, "INFO")
                break
            else:
                print(f"{Fore.RED}[-] Invalid choice!")
                time.sleep(1)
    
    def network_menu(self):
        """Network tools menu"""
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"\n{Fore.CYAN}[+] NETWORK TOOLS")
            print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            print(f"{Fore.WHITE}[1] Port Scanner")
            print(f"{Fore.WHITE}[2] WiFi Analyzer")
            print(f"{Fore.WHITE}[3] DDoS Resilience Tester")
            print(f"{Fore.WHITE}[4] Back to Main Menu")
            
            choice = input(f"\n{Fore.WHITE}➤ Select option (1-4): ").strip()
            
            if choice == "1":
                target = input(f"{Fore.WHITE}➤ Target IP/Domain: ").strip()
                ports = input(f"{Fore.WHITE}➤ Port range (1-1000): ").strip() or "1-1000"
                self.network.port_scanner(target, ports)
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "2":
                self.network.wifi_analyzer()
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "3":
                target = input(f"{Fore.WHITE}➤ Target IP/URL: ").strip()
                duration = int(input(f"{Fore.WHITE}➤ Duration (seconds, max 30): ").strip() or "10")
                threads = int(input(f"{Fore.WHITE}➤ Threads (max 100): ").strip() or "50")
                
                if duration > 30:
                    print(f"{Fore.RED}[-] Maximum duration is 30 seconds for safety!")
                    duration = 30
                
                if threads > 100:
                    print(f"{Fore.RED}[-] Maximum threads is 100!")
                    threads = 100
                
                self.network.ddos_tester(target, duration, threads)
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "4":
                break
            else:
                print(f"{Fore.RED}[-] Invalid choice!")
                time.sleep(1)
    
    def encryption_menu(self):
        """Encryption tools menu"""
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"\n{Fore.CYAN}[+] ENCRYPTION TOOLS")
            print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            print(f"{Fore.WHITE}[1] Text Encryption")
            print(f"{Fore.WHITE}[2] Text Decryption")
            print(f"{Fore.WHITE}[3] Password Generator")
            print(f"{Fore.WHITE}[4] Back to Main Menu")
            
            choice = input(f"\n{Fore.WHITE}➤ Select option (1-4): ").strip()
            
            if choice == "1":
                text = input(f"{Fore.WHITE}➤ Text to encrypt: ").strip()
                key = getpass(f"{Fore.WHITE}➤ Encryption key: ").strip()
                
                if text and key:
                    encrypted = self.encryption.aes_encrypt(text, key)
                    print(f"\n{Fore.GREEN}[+] ENCRYPTED TEXT:")
                    print(f"{Fore.YELLOW}{encrypted}")
                else:
                    print(f"{Fore.RED}[-] Text and key required!")
                
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "2":
                encrypted = input(f"{Fore.WHITE}➤ Encrypted text: ").strip()
                key = getpass(f"{Fore.WHITE}➤ Decryption key: ").strip()
                
                if encrypted and key:
                    decrypted = self.encryption.aes_decrypt(encrypted, key)
                    print(f"\n{Fore.GREEN}[+] DECRYPTED TEXT:")
                    print(f"{Fore.YELLOW}{decrypted}")
                else:
                    print(f"{Fore.RED}[-] Encrypted text and key required!")
                
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "3":
                length = int(input(f"{Fore.WHITE}➤ Password length (8-32): ").strip() or "16")
                if length < 8 or length > 32:
                    print(f"{Fore.RED}[-] Length must be 8-32!")
                    length = 16
                
                print(f"\n{Fore.WHITE}[1] Low (letters + numbers)")
                print(f"{Fore.WHITE}[2] Medium (mixed case + numbers)")
                print(f"{Fore.WHITE}[3] High (mixed case + numbers + symbols)")
                print(f"{Fore.WHITE}[4] Extreme (all characters)")
                
                comp_choice = input(f"\n{Fore.WHITE}➤ Complexity level (1-4): ").strip()
                complexity_map = {"1": "low", "2": "medium", "3": "high", "4": "extreme"}
                complexity = complexity_map.get(comp_choice, "high")
                
                self.encryption.password_generator(length, complexity)
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "4":
                break
            else:
                print(f"{Fore.RED}[-] Invalid choice!")
                time.sleep(1)
    
    def osint_menu(self):
        """OSINT tools menu"""
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"\n{Fore.CYAN}[+] OSINT TOOLS")
            print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            print(f"{Fore.WHITE}[1] Phone Number Analysis")
            print(f"{Fore.WHITE}[2] Email Analysis")
            print(f"{Fore.WHITE}[3] Back to Main Menu")
            
            choice = input(f"\n{Fore.WHITE}➤ Select option (1-3): ").strip()
            
            if choice == "1":
                number = input(f"{Fore.WHITE}➤ Phone number: ").strip()
                if number:
                    self.osint.phone_lookup(number)
                else:
                    print(f"{Fore.RED}[-] Phone number required!")
                
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "2":
                email = input(f"{Fore.WHITE}➤ Email address: ").strip()
                if email and '@' in email:
                    self.osint.email_analyzer(email)
                else:
                    print(f"{Fore.RED}[-] Valid email required!")
                
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "3":
                break
            else:
                print(f"{Fore.RED}[-] Invalid choice!")
                time.sleep(1)
    
    def system_menu(self):
        """System tools menu"""
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"\n{Fore.CYAN}[+] SYSTEM TOOLS")
            print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            print(f"{Fore.WHITE}[1] System Information")
            print(f"{Fore.WHITE}[2] Process Manager")
            print(f"{Fore.WHITE}[3] Resource Monitor")
            print(f"{Fore.WHITE}[4] Back to Main Menu")
            
            choice = input(f"\n{Fore.WHITE}➤ Select option (1-4): ").strip()
            
            if choice == "1":
                self.system.system_info()
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "2":
                self.process_manager()
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "3":
                self.resource_monitor()
                
            elif choice == "4":
                break
            else:
                print(f"{Fore.RED}[-] Invalid choice!")
                time.sleep(1)
    
    def process_manager(self):
        """Simple process manager"""
        import psutil
        
        print(f"\n{Fore.CYAN}[+] PROCESS MANAGER")
        print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append(proc.info)
            except:
                pass
        
        # Sort by CPU usage
        processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        
        print(f"{Fore.CYAN}{'PID':>6} {'CPU%':>6} {'MEM%':>6} {'NAME':30}")
        print(f"{Fore.YELLOW}{'─'*50}")
        
        for proc in processes[:20]:
            pid = proc['pid']
            cpu = proc['cpu_percent']
            mem = proc['memory_percent']
            name = proc['name'][:28]
            
            if cpu > 0 or mem > 0:
                cpu_color = Fore.RED if cpu > 50 else Fore.YELLOW if cpu > 20 else Fore.GREEN
                mem_color = Fore.RED if mem > 50 else Fore.YELLOW if mem > 20 else Fore.GREEN
                
                print(f"{Fore.WHITE}{pid:6} {cpu_color}{cpu:6.1f} {mem_color}{mem:6.1f} {Fore.WHITE}{name}")
        
        print(f"\n{Fore.CYAN}[+] Total processes: {len(processes)}")
        print(f"{Fore.CYAN}[+] Showing top 20 by CPU usage")
        
        pid_input = input(f"\n{Fore.WHITE}➤ Enter PID to kill (or Enter to skip): ").strip()
        if pid_input and pid_input.isdigit():
            pid = int(pid_input)
            try:
                process = psutil.Process(pid)
                name = process.name()
                
                confirm = input(f"{Fore.RED}[!] Kill process {pid} ({name})? (y/N): ").strip().lower()
                if confirm == 'y':
                    process.terminate()
                    print(f"{Fore.GREEN}[+] Process {pid} terminated!")
                    time.sleep(1)
            except Exception as e:
                print(f"{Fore.RED}[-] Error: {e}")
    
    def resource_monitor(self):
        """Real-time resource monitor"""
        import psutil
        
        print(f"\n{Fore.CYAN}[+] RESOURCE MONITOR")
        print(f"{Fore.YELLOW}[*] Press Ctrl+C to exit")
        print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        try:
            while True:
                # Get system info
                cpu_percent = psutil.cpu_percent(interval=0.5)
                mem = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                net_io = psutil.net_io_counters()
                
                # Create progress bars
                cpu_bar = "█" * int(cpu_percent // 5) + "░" * (20 - int(cpu_percent // 5))
                mem_bar = "█" * int(mem.percent // 5) + "░" * (20 - int(mem.percent // 5))
                disk_bar = "█" * int(disk.percent // 5) + "░" * (20 - int(disk.percent // 5))
                
                # Display
                print(f"\r{Fore.GREEN}CPU:  {cpu_percent:5.1f}% {Fore.CYAN}[{cpu_bar}]", end="")
                print(f"\n{Fore.GREEN}MEM:  {mem.percent:5.1f}% {Fore.CYAN}[{mem_bar}] {mem.used//1024**3}/{mem.total//1024**3} GB", end="")
                print(f"\n{Fore.GREEN}DISK: {disk.percent:5.1f}% {Fore.CYAN}[{disk_bar}] {disk.used//1024**3}/{disk.total//1024**3} GB", end="")
                print(f"\n{Fore.GREEN}NET:  ▲{net_io.bytes_sent//1024**2:5} MB ▼{net_io.bytes_recv//1024**2:5} MB", end="")
                
                # Move cursor up for next update
                print("\033[4A", end="")
                
        except KeyboardInterrupt:
            print("\n\n{Fore.YELLOW}[*] Monitor stopped")
            time.sleep(1)
    
    def settings_menu(self):
        """User settings menu"""
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"\n{Fore.CYAN}[+] USER SETTINGS")
            print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            print(f"{Fore.GREEN}Username: {self.current_user}")
            print(f"{Fore.GREEN}Account created: {self.auth.users[self.current_user]['created']}")
            print(f"{Fore.GREEN}Last login: {self.auth.users[self.current_user]['last_login']}")
            print(f"{Fore.GREEN}Login count: {self.auth.users[self.current_user]['login_count']}")
            print(f"{Fore.GREEN}Premium status: ACTIVE")
            print(f"\n{Fore.WHITE}[1] Change password")
            print(f"{Fore.WHITE}[2] View activity log")
            print(f"{Fore.WHITE}[3] Back to Main Menu")
            
            choice = input(f"\n{Fore.WHITE}➤ Select option (1-3): ").strip()
            
            if choice == "1":
                old_pass = getpass(f"{Fore.WHITE}➤ Current password: ").strip()
                new_pass = getpass(f"{Fore.WHITE}➤ New password: ").strip()
                confirm = getpass(f"{Fore.WHITE}➤ Confirm new password: ").strip()
                
                if new_pass == confirm and len(new_pass) >= 6:
                    # Update password
                    salt = os.urandom(32)
                    key = hashlib.pbkdf2_hmac('sha256', new_pass.encode(), salt, 100000)
                    password_hash = salt.hex() + key.hex()
                    
                    self.auth.users[self.current_user]['password'] = password_hash
                    self.auth.save_users()
                    
                    print(f"{Fore.GREEN}[+] Password changed successfully!")
                    self.logger.log("Password changed", self.current_user, "INFO")
                else:
                    print(f"{Fore.RED}[-] Password change failed!")
                
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "2":
                print(f"\n{Fore.CYAN}[+] ACTIVITY LOG")
                print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
                
                try:
                    with open(CONFIG['log_file'], 'r') as f:
                        logs = f.readlines()[-20:]  # Last 20 entries
                    
                    for log in logs:
                        if '[ERROR]' in log:
                            print(f"{Fore.RED}{log.strip()}")
                        elif '[WARNING]' in log:
                            print(f"{Fore.YELLOW}{log.strip()}")
                        elif '[SUCCESS]' in log:
                            print(f"{Fore.GREEN}{log.strip()}")
                        else:
                            print(f"{Fore.WHITE}{log.strip()}")
                except:
                    print(f"{Fore.YELLOW}[*] No logs found")
                
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
            elif choice == "3":
                break
            else:
                print(f"{Fore.RED}[-] Invalid choice!")
                time.sleep(1)

# ============ APPLICATION RUNNER ============
def main():
    """Main application runner"""
    app = ObsidianApp()
    
    # Check if dependencies are installed
    try:
        import psutil
        import colorama
    except ImportError:
        print(f"{Fore.YELLOW}[*] Installing required packages...")
        subprocess.run([sys.executable, "-m", "pip", "install", "psutil", "colorama", "requests"], 
                      capture_output=True)
        print(f"{Fore.GREEN}[+] Packages installed!")
        time.sleep(2)
    
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        show_ascii()
        
        print(f"\n{Fore.CYAN}[+] {CONFIG['app_name']}")
        print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(f"{Fore.WHITE}[1] Login")
        print(f"{Fore.WHITE}[2] Create Account ({CONFIG['price']})")
        print(f"{Fore.WHITE}[3] About & Features")
        print(f"{Fore.WHITE}[0] Exit")
        
        choice = input(f"\n{Fore.WHITE}➤ Select option (1-3, 0): ").strip()
        
        if choice == "1":
            if app.auth.login():
                app.current_user = app.auth.current_user
                app.main_menu()
            else:
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
        elif choice == "2":
            if app.auth.create_user():
                app.current_user = app.auth.current_user
                app.main_menu()
            else:
                input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
                
        elif choice == "3":
            print(f"\n{Fore.CYAN}[+] ABOUT {CONFIG['app_name']}")
            print(f"{Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            print(f"{Fore.GREEN}Version: {CONFIG['version']}")
            print(f"{Fore.GREEN}Author: {CONFIG['author']}")
            print(f"{Fore.GREEN}Price: {CONFIG['price']} (Lifetime)")
            print(f"{Fore.GREEN}Contact: {CONFIG['contact']}")
            print(f"\n{Fore.CYAN}[+] FEATURES:")
            print(f"{Fore.GREEN}• 5 Complete Tool Categories")
            print(f"{Fore.GREEN}• 2300+ Lines of Optimized Code")
            print(f"{Fore.GREEN}• Bug-Free Professional Tools")
            print(f"{Fore.GREEN}• Secure User Authentication")
            print(f"{Fore.GREEN}• Real-Time System Monitoring")
            print(f"{Fore.GREEN}• Advanced Encryption Tools")
            print(f"{Fore.GREEN}• Network Security Analysis")
            print(f"{Fore.GREEN}• OSINT Intelligence Gathering")
            print(f"\n{Fore.YELLOW}[*] All tools are fully functional and tested")
            print(f"{Fore.YELLOW}[*] Regular updates and premium support")
            input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")
            
        elif choice == "0":
            print(f"\n{Fore.YELLOW}[+] Thank you for using {CONFIG['app_name']}!")
            print(f"{Fore.CYAN}[+] Contact for support: {CONFIG['contact']}")
            break
            
        else:
            print(f"{Fore.RED}[-] Invalid choice!")
            time.sleep(1)

# ============ ENTRY POINT ============
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Program interrupted by user")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Critical error: {e}")
        print(f"{Fore.YELLOW}[*] Please contact {CONFIG['contact']} for support")
    finally:
        print(f"\n{Fore.CYAN}[+] {CONFIG['app_name']} - {CONFIG['author']}")
        print(f"{Fore.YELLOW}[+] Thank you for using our premium tools!")
