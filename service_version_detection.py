import nmap

def service_version_detection(host, port):
    nm = nmap.PortScanner()
    nm.scan(hosts=host, ports=str(port), arguments='-sV')

    print(f"Service/version detection results for {host}, port {port}:\n")

    for host in nm.all_hosts():
        if nm[host].has_tcp(port):
            service = nm[host]['tcp'][port]['name']
            version = nm[host]['tcp'][port]['version']
            state = nm[host]['tcp'][port]['state']
            if version:
                print(f"Port {port}/{nm[host]['tcp'][port]['name']} {state}: {version}")
            else:
                print(f"Port {port}/{nm[host]['tcp'][port]['name']} {state}")

if __name__ == "__main__":
    host_to_scan = '192.168.1.1' 
    port_to_detect = 80  

    service_version_detection(host_to_scan, port_to_detect)

