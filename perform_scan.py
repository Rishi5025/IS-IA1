import nmap

def perform_scan(hosts, arguments):
    nm = nmap.PortScanner()
    nm.scan(hosts=hosts, arguments=arguments)
    return nm

if __name__ == "__main__":
    hosts = "scanme.nmap.org"  # Example hosts to scan
    arguments = "-sS"  # Example scan technique (SYN scan)

    print(f"Performing scan on {hosts} with arguments: {arguments}")
    nm = perform_scan(hosts, arguments)

    print("\nScan results:")
    for host in nm.all_hosts():
        print("----------------------------------------------------")
        print(f"Host: {host}")
        print("State:", nm[host].state())
        for proto in nm[host].all_protocols():
            print("Protocol:", proto)
            ports = nm[host][proto].keys()
            for port in ports:
                state = nm[host][proto][port]["state"]
                print(f"Port {port}: {state}")

