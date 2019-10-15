import sys
from scapy.all import Ether, ARP, srp

def main():
    _range = "192.168.1.1/24"
    print("Network scan on %s\n" % _range)
    print("Host state\tIP address\tMAC address\n")
    ip, ntBits = _range.split('/')
    ip_addresses = []
    st_bit = ip.split('.')[3:4][0]   #Since it's an IPv4
    for n in range(1, int(ntBits)+1):
        eval_ip = ".".join( ip.split('.')[:-1] ) + '.' + str(n)
        ip_addresses.append( eval_ip )

    for ip in ip_addresses:
        _pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, unans = srp( _pkt, timeout=0.1, verbose=False)
        for snt, recv in ans:
            if recv:
                print ("Host Alive\t%s\t%s" % (recv[ARP].psrc, recv[Ether].src))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print ("CTRL+C pressed. Exiting. ")
        sys.exit(0)
