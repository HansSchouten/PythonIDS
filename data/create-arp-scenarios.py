import scapy
from scapy.all import *

dump = PcapWriter('arp-scenarios.pcap')

# Correct ARP request
dump.write(Ether()/ARP(op=ARP.who_has, hwsrc="08:00:27:17:f3:74", psrc="10.0.2.11", hwdst="ff:ff:ff:ff:ff:ff", pdst="10.0.2.13"))
# Correct ARP response
dump.write(Ether()/ARP(op=ARP.is_at, hwsrc="08:00:27:17:f3:00", psrc="10.0.2.13", hwdst="08:00:27:17:f3:74", pdst="10.0.2.11"))
# Additional ARP response (triggering the deviation detection mechanism)
dump.write(Ether()/ARP(op=ARP.is_at, hwsrc="08:00:27:17:f3:00", psrc="10.0.2.13", hwdst="08:00:27:17:f3:74", pdst="10.0.2.11"))

# Gratuitous request
dump.write(Ether()/ARP(op=ARP.who_has, hwsrc="08:00:27:17:f3:74", psrc="10.0.2.11", hwdst="ff:ff:ff:ff:ff:ff", pdst="10.0.2.11"))
# Destination MAC other than broadcast
dump.write(Ether()/ARP(op=ARP.who_has, hwsrc="08:00:27:17:f3:74", psrc="10.0.2.11", hwdst="08:00:27:17:f3:00", pdst="10.0.2.13"))

# Gratuitous reply
dump.write(Ether()/ARP(op=ARP.is_at, hwsrc="08:00:27:17:f3:74", psrc="10.0.2.11", hwdst="08:00:27:17:f3:74", pdst="10.0.2.11"))
# Try binding to broadcast address
dump.write(Ether()/ARP(op=ARP.is_at, hwsrc="ff:ff:ff:ff:ff:ff", psrc="10.0.2.11", hwdst="08:00:27:17:f3:00", pdst="10.0.2.13"))
# Reply with broadcast address
dump.write(Ether()/ARP(op=ARP.is_at, hwsrc="08:00:27:17:f3:16", psrc="10.0.2.11", hwdst="ff:ff:ff:ff:ff:ff", pdst="10.0.2.13"))

# Invalid binding, unknown source MAC
dump.write(Ether()/ARP(op=ARP.is_at, hwsrc="08:00:27:17:f3:ff", psrc="10.0.2.11", hwdst="08:00:27:17:f3:00", pdst="10.0.2.13"))
# Invalid binding, unknown source ip
dump.write(Ether()/ARP(op=ARP.is_at, hwsrc="08:00:27:17:f3:74", psrc="10.0.2.18", hwdst="08:00:27:17:f3:00", pdst="10.0.2.13"))
