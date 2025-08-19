import asyncio
import socket
import threading
from scapy.all import sr, IP, TCP, UDP, ICMP, RandShort, send

async def check_port_async(ip, port, stop_event):
    """Asynchronously checks if a single TCP port is open, with stop support."""
    if stop_event.is_set():
        return port, False
    try:
        # The timeout for asyncio.wait_for is crucial for responsiveness
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=0.5)
        writer.close()
        await writer.wait_closed()
        return port, True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return port, False

async def async_scan(log, ip, ports, stop_event):
    """Performs a fast, asynchronous TCP port scan."""
    print(f"[*] Starting fast TCP scan on {ip} for ports {ports[0]}-{ports[-1]}...")
    log.info(f"Starting fast TCP scan on {ip} for ports {ports[0]}-{ports[-1]}.")
    
    open_ports = []
    # Process ports in chunks to check the stop event more frequently
    chunk_size = 50
    for i in range(0, len(ports), chunk_size):
        if stop_event.is_set():
            break
        chunk = ports[i:i+chunk_size]
        tasks = [check_port_async(ip, port, stop_event) for port in chunk]
        results = await asyncio.gather(*tasks)
        for port, status in results:
            if status:
                open_ports.append(port)
                print(f"[+] Port {port} is open.")

    if open_ports:
        log.info(f"Found open TCP ports on {ip}: {open_ports}")
    else:
        if not stop_event.is_set():
            print(f"[-] No open TCP ports found in the specified range.")
            log.warning(f"No open TCP ports found on {ip} in range {ports[0]}-{ports[-1]}.")
    return open_ports

def stealth_scan(log, ip, ports, stop_event):
    """Performs a TCP SYN (stealth) scan, with improved stop support."""
    print(f"[*] Starting TCP SYN (stealth) scan on {ip} for ports {ports[0]}-{ports[-1]}...")
    log.info(f"Starting TCP SYN scan on {ip} for ports {ports[0]}-{ports[-1]}.")
    open_ports = []
    
    # Scan one port at a time with a very low timeout to make it responsive to the stop event.
    for port in ports:
        if stop_event.is_set():
            break
        # The timeout here is critical. A lower value makes the stop button more responsive.
        ans, _ = sr(IP(dst=ip)/TCP(sport=RandShort(), dport=port, flags="S"), timeout=0.2, verbose=0)
        for sent, received in ans:
            if received.haslayer(TCP) and received.getlayer(TCP).flags == 0x12: # SYN/ACK
                rst_pkt = IP(dst=ip)/TCP(sport=sent.sport, dport=sent.dport, flags="R")
                send(rst_pkt, verbose=0)
                open_ports.append(received.sport)
                print(f"[+] Port {received.sport} is open (SYN).")
    
    if open_ports:
        log.info(f"Found open TCP ports (SYN) on {ip}: {open_ports}")
    else:
        if not stop_event.is_set():
            print(f"[-] No responsive TCP ports found in SYN scan.")
    return open_ports

def udp_scan(log, ip, ports, stop_event):
    """Performs a UDP scan, with stop support."""
    print(f"[*] Starting UDP scan on {ip} for ports {ports[0]}-{ports[-1]} (this may be slow)...")
    log.info(f"Starting UDP scan on {ip} for ports {ports[0]}-{ports[-1]}.")
    
    open_ports = set(ports)
    closed_ports = set()

    chunk_size = 50
    for i in range(0, len(ports), chunk_size):
        if stop_event.is_set():
            break
        chunk = ports[i:i+chunk_size]
        ans, _ = sr(IP(dst=ip)/UDP(dport=chunk), timeout=2, verbose=0)
        for sent, received in ans:
            if received.haslayer(ICMP) and int(received.getlayer(ICMP).type) == 3 and int(received.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                closed_ports.add(sent.dport)
            elif received.haslayer(UDP):
                open_ports.add(received.sport)

    final_open_ports = sorted(list(open_ports - closed_ports))

    if final_open_ports:
        print(f"[+] Open|Filtered UDP Ports: {', '.join(map(str, final_open_ports))}")
        log.info(f"UDP scan on {ip}: Open/Filtered ports: {final_open_ports}")
    else:
        if not stop_event.is_set():
            print(f"[-] All scanned UDP ports appear to be closed.")
    return final_open_ports

def run_scan(log, target, port_range_str, scan_type, stop_event: threading.Event):
    """Orchestrates the selected scan type."""
    try:
        start_port, end_port = map(int, port_range_str.split('-'))
        ports_to_scan = list(range(start_port, end_port + 1))
    except ValueError:
        print(f"[!] Invalid port range format. Use 'start-end' (e.g., '1-1024').")
        log.error(f"Invalid port range format provided: {port_range_str}")
        return
    
    if scan_type == 'fast':
        # asyncio.run needs to be run in the main thread, but since we start this
        # in a new thread, we need to create a new event loop.
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(async_scan(log, target, ports_to_scan, stop_event))
    elif scan_type == 'stealth':
        stealth_scan(log, target, ports_to_scan, stop_event)
    elif scan_type == 'udp':
        udp_scan(log, target, ports_to_scan, stop_event)
