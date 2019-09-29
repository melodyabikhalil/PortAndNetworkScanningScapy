from scapy.all import *

dst_ip = "10.0.0.1"
src_port = RandShort()
dst_port=53
dst_timeout=10

def udp_scan(dst_ip,dst_port,dst_timeout):
    udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout, verbose=0)
    if (udp_scan_resp is None):
        retrans = []
        for count in range(0,3):
            retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout, verbose=0))
            for item in retrans:
                if (item is None):
                    udp_scan(dst_ip,dst_port,dst_timeout)
                    print ("%s | Open|Filtered" % dst_port)
                    return
                elif (udp_scan_resp.haslayer(UDP)):
                    print ("%s | Open" % dst_port)
                    return
                elif(udp_scan_resp.haslayer(ICMP)):
                    if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
                        print ("%s | Closed"% dst_port)
                        return
                    elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
                        print ("%s | Filtered" % dst_port)
                        return

udp_scan(dst_ip,dst_port,dst_timeout)
