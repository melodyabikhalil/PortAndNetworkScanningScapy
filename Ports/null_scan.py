from scapy.all import *

dst_ip = "10.0.0.1"
src_port = RandShort()
dst_port=80

def null_scan(dst_ip, dst_port, src_port):
    print("TCP Null scan on %s with port %s\n" % (dst_ip, dst_port))
    null_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags=""),timeout=10, verbose=0)
    if (null_scan_resp is None):
        return ("%s | Open|Filtered" % dst_port)
    elif(null_scan_resp.haslayer(TCP)):
        if(null_scan_resp.getlayer(TCP).flags == 0x14):
            return ("%s | Closed" % dst_port)
    elif(null_scan_resp.haslayer(ICMP)):
        if(int(null_scan_resp.getlayer(ICMP).type)==3 and int(null_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return ("%s | Filtered" % dst_port)
    else:
        return ("%s | Unknown response" % dst_port)

print(null_scan(dst_ip,dst_port,src_port))
