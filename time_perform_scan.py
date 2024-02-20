import nmap

def perform_scan(hosts, options):
    nm = nmap.PortScanner()
    nm.scan(hosts=hosts, arguments=options)
    return nm

if __name__ == "__main__":
    network = '192.168.1.0/24' 
    timing_template = '-T4'  

    options = f"{timing_template} -sS"  

    print(f"Performing scan with timing template {timing_template}...")
    scan_result = perform_scan(network, options)
    
    for host in scan_result.all_hosts():
        print(f"Host: {host}")
        for proto in scan_result[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = scan_result[host][proto].keys()
            for port in ports:
                state = scan_result[host][proto][port]['state']
                service = scan_result[host][proto][port]['name']
                print(f"Port: {port}\tState: {state}\tService: {service}")
