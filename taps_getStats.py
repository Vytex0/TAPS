import json

SORTED_FLOWS_FILENAME = "sortedFlows.json"
REAL_ATTACKERS_FILENAME = "realAttackers.json"

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
