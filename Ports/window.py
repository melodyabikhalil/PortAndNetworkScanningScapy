from scapy.all import *

dst_ip = "10.0.0.1"
src_port = RandShort()
dst_port=80

def window_scan(dst_ip,dst_port,src_port):
    print("Window scan on %s with port %s\n" % (dst_ip, dst_port))
    window_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=int(src_port),dport=int(dst_port),flags="A"),timeout=10, verbose=0)
    if (window_scan_resp is None):
        return ("Port %s : No response" % dst_port)
    elif(window_scan_resp.haslayer(TCP)):
        if(window_scan_resp.getlayer(TCP).window == 0):
            return ("Port %s : Closed" % dst_port)
        elif(window_scan_resp.getlayer(TCP).window > 0):
            return ("Port %s : Open" % dst_port)
    else:
        return ("Port %s : Unknown response" % dst_port)

