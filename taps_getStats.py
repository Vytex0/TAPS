import json
import sys
import os

########################
# Main code
if(len(sys.argv) < 3):
    print("Commande usage : ./taps_getStats.py <sorted flows file.json> <attackers list file.json>")
    sys.exit()
SORTED_FLOWS_FILENAME = sys.argv[1]
REAL_ATTACKERS_FILENAME = sys.argv[2]
if(not(os.path.isfile(SORTED_FLOWS_FILENAME))):
    print("ERROR: Captures file doesn't exist.")
    sys.exit()
if(not(os.path.isfile(REAL_ATTACKERS_FILENAME))):
    print("ERROR: Attackers list file doesn't exist.")
    sys.exit()

sortedFlowsFile = open(SORTED_FLOWS_FILENAME, "r")
flows = json.loads(sortedFlowsFile.read())
sortedFlowsFile.close()

realAttackersFile = open(REAL_ATTACKERS_FILENAME, "r")
realAttackers = json.loads(realAttackersFile.read())
realAttackersFile.close()



uniqueSources = {}
uniqueAttackers = {}

for flow in flows:
    ip = flow["key"][0]
    uniqueSources[ip] = uniqueSources.get(ip, 0)+1

for flow in realAttackers:
    ip = flow
    uniqueAttackers[ip] = uniqueAttackers.get(ip, 0)+1

print("uniquesSources =", len(uniqueSources))
print("uniqueAttackers =", len(uniqueAttackers))
