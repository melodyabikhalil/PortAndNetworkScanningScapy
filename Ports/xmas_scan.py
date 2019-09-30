from scapy.all import *

dst_ip = "10.0.0.1"
src_port = 80
dst_port=80

def xmas_scan(target, port):

    print("Xmas scan on %s with port %s" % (target, port))
    xmas_scan_resp = sr1(IP(dst=target)/TCP(dport=port,flags="FPU"),timeout=10,verbose=0)
    if (xmas_scan_resp is None):
        print ("%s | Open|Filtered" % port)
    elif(xmas_scan_resp.haslayer(TCP)):
        if(xmas_scan_resp.getlayer(TCP).flags == 0x14):
            print ("%s | Closed" % port)
    elif(xmas_scan_resp.haslayer(ICMP)):
        if(int(xmas_scan_resp.getlayer(ICMP).type)==3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print ("%s | Filtered" % port)

xmas_scan(dst_ip, dst_port)
