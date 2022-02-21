import json
from numpy import real_if_close
from scapy.all import *
import os

REAL_ATTACKERS_FILENAME = "realAttackers.json"
ATTACKERS_PCAP_FILENAME = "data/botnet-46/botnet-capture-20110815-fast-flux.pcap"

realAttackers = {}

def extractAttacker(packet):
    global realAttackers
    try:
        src = packet.payload.src
        realAttackers[src] = realAttackers.get(src, 0)+1
    except:
        return None

sniff(offline=ATTACKERS_PCAP_FILENAME,prn=extractAttacker,store=0)

print("Registering real attackers")
try:   
    os.remove(REAL_ATTACKERS_FILENAME)
except:
    pass
f = open(REAL_ATTACKERS_FILENAME, "w")
f.write(json.dumps(realAttackers))
f.close()
print("Real attackers registered")