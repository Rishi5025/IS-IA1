import nmap

def port_specification_scan_order(host, ports):
    nm = nmap.PortScanner()
    nm.scan(hosts=host, ports=ports)
    for host in nm.all_hosts():
        print(f"Nmap scan report for {host}")
        print("----------------------------------------------")
        for proto in nm[host].all_protocols():
            print(f"PORT\t\tSTATE\t\tSERVICE")
            for port in sorted(nm[host][proto].keys()):
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port]['name']
                print(f"{port}/{proto}\t\t{state}\t\t{service}")

if __name__ == "__main__":
    host_to_scan = '192.168.1.1'  
    ports = '80,443,22,8080'  

    print(f"Starting Nmap scan for {host_to_scan}...")
    port_specification_scan_order(host_to_scan, ports)
