from ipaddress import IPv4Network
import random
from scapy.all import ICMP, IP, sr1, TCP

# Define IP range to ping
network = "192.168.1.0/30"

def remote_network_scan(network):
    # make list of addresses out of network, set live host counter
    addresses = IPv4Network(network)
    live_count = 0
    alive_hosts = []
    # Send ICMP ping request, wait for answer
    for host in addresses:
        if (host in (addresses.network_address, addresses.broadcast_address)):
            # Skip network and broadcast addresses
            continue

        resp = sr1(
            IP(dst=str(host))/ICMP(),
            timeout=2,
            verbose=0,
        )
        status =str()
        
        if resp is not None:
            if (
                int(resp.getlayer(ICMP).type)==3 and
                int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
            ):
                status ='Blocking ICMP'
                print(f"{host} is blocking ICMP.")
            else:
                status = 'Responding'
                print(f"{host} is responding.")
                live_count += 1
            host_info = {'ip':host,'status':status}
            alive_hosts.append(host_info)

    if (len(alive_hosts) == 0):
        print('No hosts are online')
        return 'No hosts are online'
    else :
        return alive_hosts

remote_network_scan(network)
