import json
from numpy import real_if_close
from scapy.all import *
import os
import sys

realAttackers = {}

def extractAttacker(packet):
    global realAttackers
    try:
        src = packet.payload.src
        realAttackers[src] = realAttackers.get(src, 0)+1
    except:
        return None

########################
# Main code
if(len(sys.argv) < 3):
    print("Commande usage : ./taps_getRealAttackers.py <input pcap attackers captures.pcap> <output attackers.json>")
    sys.exit()
ATTACKERS_PCAP_FILENAME = sys.argv[1]
REAL_ATTACKERS_FILENAME = sys.argv[2]
if(not(os.path.isfile(ATTACKERS_PCAP_FILENAME))):
    print("ERROR: Captures file doesn't exist.")
    sys.exit()
if(os.path.isfile(REAL_ATTACKERS_FILENAME)):
    print("ERROR: Please remove already existing attackers list file.")
    sys.exit()

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