from scapy.all import *

dst_ip = "8.8.8.8"
src_port = RandShort()
dst_port=80

def fin_scan(target, port):
    
    print("Fin scan on %s with port %s" % (dst_ip, port))
    fin_scan_resp = sr1(IP(dst=target)/TCP(dport=port,flags="F"),timeout=10, verbose=0)
    if (fin_scan_resp is None):
        print ("%s | Open|Filtered" % port)
    elif(fin_scan_resp.haslayer(TCP)):
        if(fin_scan_resp.getlayer(TCP).flags == 0x14):
            print ("%s | Closed" % port)
    elif(fin_scan_resp.haslayer(ICMP)):
        if(int(fin_scan_resp.getlayer(ICMP).type)==3 and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print ("%s | Filtered" % port)

fin_scan(dst_ip,dst_port)
