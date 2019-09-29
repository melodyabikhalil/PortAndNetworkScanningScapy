from scapy.all import *

dst_ip = "10.0.0.1"
src_port = RandShort()
dst_port=80

def connect_scan(target,port):
    tcp_connect_scan_resp = sr1(IP(dst=target)/TCP(sport=src_port,dport=port,flags="S"),timeout=10, verbose=0)
    if(tcp_connect_scan_resp is None):
        print ("Closed")
    elif(tcp_connect_scan_resp.haslayer(TCP)):
        if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10, verbose=0)
            print ("Open")
        elif(tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
            print ("Closed")

connect_scan(dst_ip, dst_port)
