import nmap

def script_scan(host):
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments='-sC')

    for host in nm.all_hosts():
        print(f"Nmap scan report for {host}")
        for proto in nm[host].all_protocols():
            print(f"PORT   STATE SERVICE")
            ports = nm[host][proto].keys()
            for port in ports:
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port]['name']
                print(f"{port}/tcp {state:<6} {service}")
                scripts = nm[host][proto][port]['script']
                for script in scripts:
                    script_id = script['id']
                    output = script['output']
                    print(f"    {script_id:<20} {output.strip()}")

if __name__ == "__main__":
    host_to_scan = '192.168.1.1'  

    print(f"Starting Nmap script scan on {host_to_scan}...\n")
    script_scan(host_to_scan)

