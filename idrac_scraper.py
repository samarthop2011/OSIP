#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  ██╗██████╗     ███████╗ ██████╗██████╗  █████╗ ██████╗ ███████╗██████╗      ║
║  ██║██╔══██╗    ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗     ║
║  ██║██████╔╝    ███████╗██║     ██████╔╝███████║██████╔╝█████╗  ██████╔╝     ║
║  ██║██╔═══╝     ╚════██║██║     ██╔══██╗██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗     ║
║  ██║██║         ███████║╚██████╗██║  ██║██║  ██║██║     ███████╗██║  ██║     ║
║  ╚═╝╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝     ║
║                    iDRAC CVE Intelligence Gatherer v1.0                      ║
║                           Coded by SAM                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import requests
import sqlite3
import json
import time
import random
import threading
import queue
import re
import urllib3
from datetime import datetime
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# CVE Database
CVES = {
    "CVE-2018-1207": {"desc": "iDRAC 7/8 Authentication Bypass", "ports": [443, 80]},
    "CVE-2024-54085": {"desc": "iDRAC9 Command Injection", "ports": [443, 80]},
    "CVE-2024-36435": {"desc": "iDRAC9 Information Disclosure", "ports": [443, 80]},
    "CVE-2018-1211": {"desc": "iDRAC 7/8 Path Traversal", "ports": [443, 80]},
    "CVE-2019-3705": {"desc": "iDRAC Buffer Overflow", "ports": [443, 80]},
    "CVE-2019-3706": {"desc": "iDRAC9 Auth Bypass", "ports": [443, 80]},
    "CVE-2019-3707": {"desc": "iDRAC9 WS-MAN Auth Bypass", "ports": [443, 80, 623]},
    "CVE-2020-5344": {"desc": "iDRAC Buffer Overflow RCE", "ports": [443, 80]},
    "CVE-2021-21505": {"desc": "iDRAC Undocumented Account", "ports": [443, 80]},
    "CVE-2021-21538": {"desc": "iDRAC9 Virtual Console Bypass", "ports": [443, 80, 5900]},
    "CVE-2022-24422": {"desc": "iDRAC9 VNC Console Bypass", "ports": [443, 80, 5900, 5901]}
}

SHODAN_DORKS = [
    'title:"iDRAC 8" port:443',
    'title:"iDRAC 7" port:443',
    'title:"iDRAC 9" port:443',
    'title:"Integrated Dell Remote Access Controller"',
    'html:"iDRAC" port:443',
    'html:"/restgui/start.html"',
]

FOFA_DORKS = [
    'title="iDRAC 8"',
    'title="iDRAC 7"',
    'title="iDRAC 9"',
    'body="iDRAC" && protocol="https"',
    'app="DELL-iDRAC" || app="DELL-iDRAC-8"',
]

GITHUB_DORKS = [
    'iDRAC 8 ip:443',
    'iDRAC 7 ip:443',
    'iDRAC 9 console',
    'dell idrac ip list',
    'idrac vulnerable',
]

GOOGLE_DORKS = [
    'intitle:"iDRAC 8" inurl:/restgui/',
    'intitle:"iDRAC 7" inurl:/restgui/',
    'intitle:"iDRAC 9" inurl:/restgui/',
    'intitle:"Integrated Dell Remote Access Controller 8"',
    'inurl:/cgi-bin/putfile intitle:iDRAC',
    'intitle:"iDRAC" "Version 2.50" | "Version 2.60"',
]

TOR_SEARCH_URLS = [
    "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion",  # Ahmia
]

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class IPScraper:
    def __init__(self, db_path="idrac_targets.db"):
        self.db_path = db_path
        self.ip_queue = queue.Queue()
        self.found_ips = set()
        self.lock = threading.Lock()
        self.init_db()
        self.print_banner()
        
    def print_banner(self):
        print(f"""{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║  ██╗██████╗     ███████╗ ██████╗██████╗  █████╗ ██████╗ ███████╗██████╗      ║
║  ██║██╔══██╗    ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗     ║
║  ██║██████╔╝    ███████╗██║     ██████╔╝███████║██████╔╝█████╗  ██████╔╝     ║
║  ██║██╔═══╝     ╚════██║██║     ██╔══██╗██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗     ║
║  ██║██║         ███████║╚██████╗██║  ██║██║  ██║██║     ███████╗██║  ██║     ║
║  ╚═╝╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝     ║
║                    iDRAC CVE Intelligence Gatherer v1.0                      ║
║                           Coded by SAM                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.END}
{Colors.YELLOW}[+] CVE Coverage: CVE-2018-1207, CVE-2024-54085, CVE-2024-36435, and 8 more...
[+] Sources: Shodan, Fofa, GitHub, Google Dorks, Tor Network
[+] Output: SQLite Database (idrac_targets.db)
[+] Status: Initializing...{Colors.END}
""")
        
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            port INTEGER,
            source TEXT,
            cve_tags TEXT,
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            checked INTEGER DEFAULT 0,
            vulnerable INTEGER DEFAULT 0,
            details TEXT
        )''')
        conn.commit()
        conn.close()
        
    def add_ip(self, ip, port, source, cve_tags=""):
        with self.lock:
            if ip in self.found_ips:
                return False
            self.found_ips.add(ip)
            
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("INSERT OR IGNORE INTO targets (ip, port, source, cve_tags) VALUES (?, ?, ?, ?)",
                     (ip, port, source, cve_tags))
            conn.commit()
            conn.close()
            print(f"{Colors.GREEN}[+] New target: {ip}:{port} from {source}{Colors.END}")
            return True
        except Exception as e:
            print(f"{Colors.RED}[-] DB Error: {e}{Colors.END}")
            return False
    
    def scrape_shodan(self, api_key=None):
        print(f"{Colors.CYAN}[*] Initiating Shodan reconnaissance...{Colors.END}")
        if not api_key:
            print(f"{Colors.YELLOW}[!] Shodan API key not provided, using web scraping fallback...{Colors.END}")
            return self._shodan_web_scrape()
        
        try:
            for dork in SHODAN_DORKS:
                url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={dork}&limit=100"
                resp = requests.get(url, timeout=30)
                data = resp.json()
                
                for match in data.get('matches', []):
                    ip = match.get('ip_str')
                    port = match.get('port', 443)
                    self.add_ip(ip, port, "Shodan_API", "iDRAC_Multi_CVE")
                    
                time.sleep(1)
        except Exception as e:
            print(f"{Colors.RED}[-] Shodan API error: {e}{Colors.END}")
    
    def _shodan_web_scrape(self):
        print(f"{Colors.YELLOW}[*] Shodan web scraping module (limited without API)...{Colors.END}")
        # Fallback: parse shodan search results if no API
        pass
    
    def scrape_fofa(self, email=None, key=None):
        print(f"{Colors.CYAN}[*] Initiating Fofa reconnaissance...{Colors.END}")
        if not (email and key):
            print(f"{Colors.YELLOW}[!] Fofa credentials required{Colors.END}")
            return
            
        try:
            for dork in FOFA_DORKS:
                query = base64.b64encode(dork.encode()).decode()
                url = f"https://fofa.info/api/v1/search/all?email={email}&key={key}&qbase64={query}&size=100"
                resp = requests.get(url, timeout=30)
                data = resp.json()
                
                for result in data.get('results', []):
                    ip_port = result[0]
                    if ':' in ip_port:
                        ip, port = ip_port.rsplit(':', 1)
                        self.add_ip(ip, int(port), "Fofa", "iDRAC_Multi_CVE")
                time.sleep(1)
        except Exception as e:
            print(f"{Colors.RED}[-] Fofa error: {e}{Colors.END}")
    
    def scrape_github(self, token=None):
        print(f"{Colors.CYAN}[*] Initiating GitHub code search...{Colors.END}")
        headers = {}
        if token:
            headers['Authorization'] = f'token {token}'
            
        try:
            for dork in GITHUB_DORKS:
                url = f"https://api.github.com/search/code?q={dork}&per_page=100"
                resp = requests.get(url, headers=headers, timeout=30)
                data = resp.json()
                
                for item in data.get('items', []):
                    raw_url = item.get('html_url', '').replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
                    if raw_url:
                        try:
                            content = requests.get(raw_url, timeout=10).text
                            ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)
                            for ip in ips:
                                if self._validate_ip(ip):
                                    self.add_ip(ip, 443, "GitHub", "iDRAC_Multi_CVE")
                        except:
                            pass
                time.sleep(2)
        except Exception as e:
            print(f"{Colors.RED}[-] GitHub error: {e}{Colors.END}")
    
    def _validate_ip(self, ip):
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except:
            return False
    
    def scrape_google_dorks(self):
        print(f"{Colors.CYAN}[*] Initiating Google dorking module...{Colors.END}")
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        for dork in GOOGLE_DORKS:
            try:
                url = f"https://www.google.com/search?q={requests.utils.quote(dork)}&num=100"
                resp = requests.get(url, headers=headers, timeout=30)
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                links = soup.find_all('a')
                for link in links:
                    href = link.get('href', '')
                    if 'http' in href:
                        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', href)
                        if ip_match:
                            ip = ip_match.group()
                            if self._validate_ip(ip):
                                self.add_ip(ip, 443, "Google_Dork", "iDRAC_Multi_CVE")
                time.sleep(random.uniform(2, 5))
            except Exception as e:
                print(f"{Colors.RED}[-] Google dork error: {e}{Colors.END}")
    
    def scrape_tor(self):
        print(f"{Colors.CYAN}[*] Initiating Tor network reconnaissance...{Colors.END}")
        print(f"{Colors.MAGENTA}[!] Tor scraping requires Tor proxy: 127.0.0.1:9050{Colors.END}")
        
        proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        
        tor_dorks = [
            'iDRAC vulnerable',
            'dell idrac exploit',
            'iDRAC 8 bypass',
        ]
        
        for search_url in TOR_SEARCH_URLS:
            for dork in tor_dorks:
                try:
                    url = f"{search_url}/search/?q={dork}"
                    resp = requests.get(url, proxies=proxies, timeout=30)
                    content = resp.text
                    
                    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)
                    for ip in ips:
                        if self._validate_ip(ip):
                            self.add_ip(ip, 443, "Tor_Network", "iDRAC_Multi_CVE")
                except Exception as e:
                    print(f"{Colors.RED}[-] Tor error: {e}{Colors.END}")
    
    def run_all(self):
        print(f"{Colors.BOLD}{Colors.GREEN}[*] Starting multi-source intelligence gathering...{Colors.END}\n")
        
        threads = []
        
        # Web Sources
        threads.append(threading.Thread(target=self.scrape_shodan))
        threads.append(threading.Thread(target=self.scrape_github))
        threads.append(threading.Thread(target=self.scrape_google_dorks))
        threads.append(threading.Thread(target=self.scrape_tor))
        
        for t in threads:
            t.daemon = True
            t.start()
            
        try:
            while True:
                time.sleep(1)
                print(f"{Colors.BLUE}[*] Active threads: {threading.active_count()} | Unique IPs: {len(self.found_ips)}{Colors.END}", end='\r')
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Scraper stopped by user{Colors.END}")
            print(f"{Colors.GREEN}[+] Total unique IPs collected: {len(self.found_ips)}{Colors.END}")

if __name__ == "__main__":
    scraper = IPScraper()
    scraper.run_all()
