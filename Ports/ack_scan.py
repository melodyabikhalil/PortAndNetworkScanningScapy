from scapy.all import *

dst_ip = "10.0.0.1"
src_port = RandShort()
dst_port=80


def ack_scan(target, port):
    print("ACK scan on %s with port %s" % (target, port))
    ack_flag_scan_resp = sr1(IP(dst=target)/TCP(dport=port,flags="A"),timeout=10, verbose=0)
    if (ack_flag_scan_resp is None):
        print( "%s | Stateful firewall present(Filtered)" % port)
    elif(ack_flag_scan_resp.haslayer(TCP)):
        if(ack_flag_scan_resp.getlayer(TCP).flags == 0x4):
            print ("%s | No firewall(Unfiltered)" % port)
    elif(ack_flag_scan_resp.haslayer(ICMP)):
        if(int(ack_flag_scan_resp.getlayer(ICMP).type)==3 and int(ack_flag_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print ("%s | Stateful firewall present(Filtered)" % port)

ack_scan(dst_ip,dst_port)
