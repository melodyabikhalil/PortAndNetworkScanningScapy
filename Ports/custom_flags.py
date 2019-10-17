from scapy.all import *

dst_ip = "10.0.0.1"
src_port = 80
dst_port=80
flags='FPU'

def custom_flags_scan(dst_ip, dst_port, src_port, flags):
    if (flags==''):
        return ('No inserted flags')
    print("Port scan with custom flags on %s with port %s\n" % (dst_ip, dst_port))
    custom_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=int(src_port),dport=int(dst_port),flags=flags),timeout=10,verbose=0)
    if (custom_scan_resp is None):
        return ('Port %s No Response' % dst_port)
    else:
        return(custom_scan_resp.summary())


