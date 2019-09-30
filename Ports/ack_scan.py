from scapy.all import *

dst_ip = "10.0.0.1"
src_port = RandShort()
dst_port=80


def ack_scan(dst_ip, dst_port, src_port):
    print("ACK scan on %s with port %s\n" % (dst_ip, dst_port))
    ack_flag_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="A"),timeout=10, verbose=0)
    if (ack_flag_scan_resp is None):
        return( "%s | Stateful firewall present(Filtered)" % dst_port)
    elif(ack_flag_scan_resp.haslayer(TCP)):
        if(ack_flag_scan_resp.getlayer(TCP).flags == 0x4):
            return ("%s | No firewall(Unfiltered)" % dst_port)
    elif(ack_flag_scan_resp.haslayer(ICMP)):
        if(int(ack_flag_scan_resp.getlayer(ICMP).type)==3 and int(ack_flag_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return ("%s | Stateful firewall present(Filtered)" % dst_port)
    else:
        return ("%s | Unknown response" % dst_port)

print(ack_scan(dst_ip,dst_port,src_port))
