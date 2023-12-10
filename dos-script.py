
from scapy.all import TCP, IP, sr1

dstaddress = input('Destination address: ')

while True:
    p = sr1(IP(dst=dstaddress)/TCP(flags='SA'))
    p.show()