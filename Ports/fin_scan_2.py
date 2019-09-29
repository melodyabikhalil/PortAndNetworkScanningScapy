from scapy.all import *

def print_ports(port, state):
    print("%s | %s" % (port, state))

def syn_scan(target, ports):
    print("FIN scan on, %s with ports %s\n" % (target, ports))
    sport = RandShort()
    for port in ports:
        pkt = sr1(IP(dst=target)/TCP(sport=sport, dport=port, flags="F"), timeout=1, verbose=0)
        if pkt != None:
            if pkt.haslayer(TCP):
                if pkt[TCP].flags == 0x14:
                    print_ports(port, "Closed")
            elif pkt.haslayer(ICMP):
                if(int(fin_scan_resp.getlayer(ICMP).type)==3 and (fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    print_ports(port, "Filtered")
            else:
                print_ports(port, "Unknown response")
                print(pkt.summary())
        else:
            print_ports(port, "Open|Filtered")
			
syn_scan("8.8.8.8", range(20,100))
