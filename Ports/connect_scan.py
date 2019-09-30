from scapy.all import *

dst_ip = "10.0.0.1"
src_port = RandShort()
dst_port=80

def connect_scan(dst_ip,dst_port, scr_port):
    print("TCP Connect scan on, %s with ports %s\n" % (dst_ip, dst_port))
    tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10, verbose=0)
    if(tcp_connect_scan_resp is None):
        return ("%s | Closed" % dst_port)
    elif(tcp_connect_scan_resp.haslayer(TCP)):
        if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10, verbose=0)
            return ("%s | Open" % dst_port)
        elif(tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
            return ("%s | Closed" % dst_port)
    else:
        return ("%s | Unknown response" % dst_port)

print(connect_scan(dst_ip, dst_port, src_port))
