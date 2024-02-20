import nmap

def host_discovery(network):
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()}) is {'up' if nm[host]['status']['state'] == 'up' else 'down'}")

if __name__ == "__main__":
    network = '192.168.1.0/24' 

    print("Discovering hosts...")
    host_discovery(network)

