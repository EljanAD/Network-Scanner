import nmap
import socket
from datetime import datetime


def resolve_target(target):
    try:
        ip = socket.gethostbyname(target)
        return ip
    except:
        print("Could not resolve hostname.")
        return None


def port_scan(target, start_port, end_port):
    print(f"Scanning target: {target} for open ports from {start_port} to {end_port}...")
    open_ports = []

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        if result == 0:
            open_ports.append(port)

        sock.close()

    return open_ports


def banner_grab(target, port):
    print(f"Grabbing banner for {target}:{port}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target, port))
        sock.settimeout(2)

        banner = sock.recv(1024).decode('utf-8', errors='ignore')

        sock.close()
        return banner.strip()

    except:
        return None


def vulnerability_scan(target):
    print(f"Scanning target {target} for vulnerabilities...")

    nm = nmap.PortScanner()

    try:
        nm.scan(hosts=target, arguments="-O -sV --script=vuln")
        return nm

    except Exception as e:
        print(f"Error during vulnerability scan: {e}")
        return None


def scan(target, start_port, end_port):
    print(f"Starting network scan for target: {target}..")

    start_time = datetime.now()

    target_ip = resolve_target(target)
    if not target_ip:
        return

    open_ports = port_scan(target_ip, start_port, end_port)

    if open_ports:
        print(f"Open ports found: {open_ports}")
    else:
        print("No open ports found.")

    for port in open_ports:
        banner = banner_grab(target_ip, port)

        if banner:
            print(f"Banner for {target_ip}:{port} = {banner}")
        else:
            print(f"No banner found for {target_ip}:{port}")

    vuln_info = vulnerability_scan(target_ip)

    if vuln_info:
        for host in vuln_info.all_hosts():

            if 'hostnames' in vuln_info[host]:
                print(f"Hostnames: {vuln_info[host]['hostnames']}")

            if 'osmatch' in vuln_info[host]:
                print("\nOperating System guesses:")
                for os in vuln_info[host]['osmatch']:
                    print(os['name'])

            for proto in vuln_info[host].all_protocols():
                ports = vuln_info[host][proto].keys()

                for port in ports:
                    service = vuln_info[host][proto][port]

                    if 'script' in service:
                        print(f"\nVulnerabilities for port {port}:")
                        for script, output in service['script'].items():
                            print(f"{script}:")
                            print(output)

    else:
        print("No vulnerabilities detected.")

    end_time = datetime.now()
    print(f"Scan completed in: {end_time - start_time}")


if __name__ == "__main__":
    target_ip = input("Enter the target IP or hostname: ")
    start_port = int(input("Enter the starting port for scanning: "))
    end_port = int(input("Enter the ending port for scanning: "))

    scan(target_ip, start_port, end_port)
