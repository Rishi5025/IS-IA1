import nmap

def detect_os(host):
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments='-O')
    for host in nm.all_hosts():
        os_match = nm[host]['osmatch']
        if os_match:
            print(f"OS detection results for {host}:")
            for os_info in os_match:
                print(f"OS Name: {os_info['name']}, Accuracy: {os_info['accuracy']}")
        else:
            print(f"No OS detection results for {host}")

if __name__ == "__main__":
    host_to_scan = '192.168.1.1' 
    print(f"Detecting OS for host {host_to_scan}...")
    detect_os(host_to_scan)
