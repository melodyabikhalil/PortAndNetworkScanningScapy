from scapy.all import *

dst_ip = "10.0.0.1"
src_port = RandShort()
dst_port=53


def udp_scan(dst_ip,dst_port,src_port):
    print("UDP scan on, %s with ports %s" % (dst_ip, dst_port))
    udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(sport=int(src_port), dport=int(dst_port)), timeout=10, verbose=0)
    if udp_scan_resp is None:
        return ("Port %s : Open|Filtered" % dst_port)
    elif udp_scan_resp.haslayer(ICMP):
        return ("Port %s : Closed"% dst_port)
    elif udp_scan_resp.haslayer(UDP):
        return ("Port %s : Open|Filtered" % dst_port)
    else:
        return ("Port %s : Unknown response" % dst_port)


