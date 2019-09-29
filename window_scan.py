from scapy.all import *

dst_ip = "10.0.0.1"
src_port = RandShort()
dst_port=80

def window_scan(target,port):
    print("Window scan on %s with port %s" % (target, port))
    window_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="A"),timeout=10, verbose=0)
    if (window_scan_resp is None):
        print ("%s | No response" % port)
    elif(window_scan_resp.haslayer(TCP)):
        if(window_scan_resp.getlayer(TCP).window == 0):
            print ("%s | Closed" % port)
        elif(window_scan_resp.getlayer(TCP).window > 0):
            print ("%s | Open" % port)

window_scan(dst_ip,dst_port)
