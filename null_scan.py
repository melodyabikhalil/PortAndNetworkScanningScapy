from scapy.all import *

dst_ip = "10.0.0.1"
src_port = RandShort()
dst_port=80

def null_scan(target,port):
    print("Null scan on %s with port %s" % (target, port))
    null_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags=""),timeout=10, verbose=0)
    if (null_scan_resp is None):
        print ("%s | Open|Filtered" % port)
    elif(null_scan_resp.haslayer(TCP)):
        if(null_scan_resp.getlayer(TCP).flags == 0x14):
            print ("%s | Closed" % port)
    elif(null_scan_resp.haslayer(ICMP)):
        if(int(null_scan_resp.getlayer(ICMP).type)==3 and int(null_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print ("%s | Filtered" % port)

null_scan(dst_ip,dst_port)
