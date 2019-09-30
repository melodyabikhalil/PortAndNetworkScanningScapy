from ipaddress import IPv4Network
import random
from scapy.all import ICMP, IP, sr1, TCP

# Define IP range to ping
network = "192.168.40.0/24"

# make list of addresses out of network, set live host counter
addresses = IPv4Network(network)
live_count = 0

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

    if resp is None:
        print(f"{host} is down or not responding.")
    elif (
        int(resp.getlayer(ICMP).type)==3 and
        int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
    ):
        print(f"{host} is blocking ICMP.")
    else:
        print(f"{host} is responding.")
        live_count += 1

print(f"{live_count}/{addresses.num_addresses} hosts are online.")
