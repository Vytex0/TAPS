from scapy.all import *

# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap('data/testSmall.pcap')

print("summary")
packets.summary() 

for packet in packets:
    #if packet.haslayer(UDP):
    if(packet.haslayer(TCP)):
        print(packet.time, packet.dport)  
# Let's iterate through every packet
#for packet in packets:
   # print(packet)
   # break
    # We're only interested packets with a DNS Round Robin layer
    #if packet.haslayer(DNSRR):
        # If the an(swer) is a DNSRR, print the name it replied with.
        #if isinstance(packet.an, DNSRR):
            #print(packet.an.rrname)