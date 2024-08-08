import nmap

def nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(target,'0-1023')
    for host in nm.all_hosts():
        print('Host: %s(%s)' % (host,nm[host].hostname()))
        print('State: %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('~~~~~~~~~~~~~~~~~~~~~~~~~')
            print('Protocol:%s' % proto)
            lport = nm[host][proto].keys()
            lport = sorted(map(int,lport))
            for port in lport:
                print ('port:%s\tstate:%s' % (port,nm[host][proto][port]['state']))

target = input("Enter the target IP for scanning: ")
nmap_scan(target)