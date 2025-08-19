import subprocess
import sys
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import queue

def scan_wifi(log):
    """Finds nearby Wi-Fi networks using the Windows 'netsh' command."""
    if sys.platform != "win32":
        print("Wi-Fi scanning is only available on Windows.")
        return

    print("[*] Scanning for Wi-Fi networks...")
    log.info("Starting Wi-Fi scan.")
    try:
        # This command creates a new process window that is hidden from the user.
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        
        # Execute the command without a shell for better security and control.
        result = subprocess.check_output(['netsh', 'wlan', 'show', 'network'], 
                                         startupinfo=startupinfo, stderr=subprocess.DEVNULL, text=True)
        print("\n--- Available Wi-Fi Networks ---")
        print(result)
        log.info("Wi-Fi scan completed successfully.")
    except (subprocess.CalledProcessError, FileNotFoundError):
        error_msg = "[!] Error: Could not execute 'netsh wlan show network'.\n    Please ensure your computer's Wi-Fi is enabled and drivers are installed."
        print(error_msg)
        log.error(error_msg)

def crawl_website(log, base_url, max_depth=2):
    """Crawls a website to find internal links up to a specific depth."""
    print(f"[*] Starting web crawl on {base_url} (depth: {max_depth})...")
    log.info(f"Starting web crawl on {base_url} with depth {max_depth}")
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'http://' + base_url
    
    try:
        domain_name = urlparse(base_url).hostname
        visited = set()
        to_visit = queue.Queue()
        to_visit.put((base_url, 0))

        with requests.Session() as session:
            session.headers.update({'User-Agent': 'Leopard-Crawler/2.1'})
            while not to_visit.empty() and len(visited) < 500: # Overall limit
                current_url, current_depth = to_visit.get()

                if current_url in visited or current_depth > max_depth:
                    continue
                
                print(f"  -> Crawling (Depth {current_depth}): {current_url}")
                visited.add(current_url)

                try:
                    response = session.get(current_url, timeout=5, allow_redirects=True)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        full_url = urljoin(base_url, link['href'])
                        if urlparse(full_url).hostname == domain_name and full_url not in visited:
                            to_visit.put((full_url, current_depth + 1))
                except requests.RequestException as e:
                    print(f"  [!] Could not fetch {current_url}: {e}")
        print(f"\n[+] Crawl finished. Discovered {len(visited)} unique links.")
    except Exception as e:
        print(f"[!] An error occurred during the web crawl: {e}")