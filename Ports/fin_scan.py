from scapy.all import *

dst_ip = "8.8.8.8"
src_port = RandShort()
dst_port=80

def fin_scan(dst_ip, dst_port, src_port):
    
    print("TCP FIN scan on %s with port %s\n" % (dst_ip, dst_port))
    fin_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="F"),timeout=10, verbose=0)
    if (fin_scan_resp is None):
        return ("%s | Open|Filtered" % dst_port)
    elif(fin_scan_resp.haslayer(TCP)):
        if(fin_scan_resp.getlayer(TCP).flags == 0x14):
            return ("%s | Closed" % dst_port)
    elif(fin_scan_resp.haslayer(ICMP)):
        if(int(fin_scan_resp.getlayer(ICMP).type)==3 and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return ("%s | Filtered" % dst_port)
    else:
        return ("%s | Unknown response" % dst_port)

print(fin_scan(dst_ip,dst_port, src_port))
