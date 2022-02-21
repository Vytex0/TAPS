from scapy.all import *
import json
import os
import os.path
import time
import sys

#https://appdividend.com/2022/01/28/how-to-convert-python-list-to-json/

FLOW_MAX_DURATION_SECONDS = 60 # in seconds
NB_PACKETS = 4479658

flowsList = []
currentFlowsList = []
sortedFlowsList = []

packetsTreated = 0

algoStartTime = time.time()

def convertSecondsToPrintableTime(seconds):
    if(seconds < 60):
        return str(seconds)+"s"
    if(seconds < 3600):
        return str(int(seconds//60))+"m "+str(int(seconds%60))+"s"
    return str(int(seconds//3600))+"h "+str(int((seconds%3600)%60))+"m "+str(int(seconds%60))+"s"

def getPacketTime(packet):
    return float(packet.time)

def getPacketKey(packet):
    # try if packets have sport, dport, ....
    try:
        return (packet.payload.src, packet.payload.dst, packet.payload.sport, packet.payload.dport, packet.payload.proto)
    except:
        return None

def clearCurrentFlowsList(flowsList, currentFlowsList, currentPacketTime):
    global FLOW_MAX_DURATION_SECONDS
    global algoStartTime
    global packetsTreated

    print("-- - - - - --")
    print("flowsList size before cleaning :", len(flowsList))
    print("currentFlowsList size before cleaning :", len(currentFlowsList))

    flowsIndexToRemoveFromCurrent = []
    for flowIndex in range(len(currentFlowsList)):
        flow = currentFlowsList[flowIndex]
        if((currentPacketTime - flow["endTime"]) > FLOW_MAX_DURATION_SECONDS):
            flowsList.append(currentFlowsList[flowIndex])
            flowsIndexToRemoveFromCurrent.append(flowIndex)

    flowsIndexToRemoveFromCurrent.reverse()
    for index in range(len(flowsIndexToRemoveFromCurrent)):
        currentFlowsList.pop(index)

    print("flowsList size after cleaning :", len(flowsList))
    print("")
    print("currentFlowsList size after cleaning :", len(currentFlowsList))
    print("time spent :", convertSecondsToPrintableTime(time.time() - algoStartTime))
    print("estimated remaining time :", convertSecondsToPrintableTime((time.time() - algoStartTime)/(packetsTreated/NB_PACKETS)))
    print("-- - - - - --")

    return (flowsList, currentFlowsList)

def findCurrentFlowIndex(currentFlowsList, packetKey, maxEndTime):
    for flowIndex in range(len(currentFlowsList)):
        flow = currentFlowsList[flowIndex]
        if(flow["key"] == packetKey):
            if(maxEndTime <= flow["endTime"]):
                return flowIndex

    return -1

def addToFlowsList(packet):
    global FLOW_MAX_DURATION_SECONDS
    global flowsList
    global currentFlowsList
    global packetsTreated

    packetsTreated += 1

    if(packetsTreated % 1000 == 0):
        print("packetsTreated :",packetsTreated,"/",NB_PACKETS, "(", int(packetsTreated/NB_PACKETS*10000)/100,"% )")

    flow = {}
    
    packetKey = getPacketKey(packet)
    if(packetKey != None):
        flow["key"] = packetKey
        flow["startTime"] = getPacketTime(packet)
        flow["endTime"] = getPacketTime(packet)
 
        maxEndTime = getPacketTime(packet) - FLOW_MAX_DURATION_SECONDS

        if(packetsTreated%10000 == 0):
            (flowsList, currentFlowsList) = clearCurrentFlowsList(flowsList, currentFlowsList, getPacketTime(packet))

        existingFlowIndex = findCurrentFlowIndex(currentFlowsList, packetKey, maxEndTime)

        if(existingFlowIndex != -1):
            flow["startTime"] = currentFlowsList[existingFlowIndex]["startTime"]

            currentFlowsList[existingFlowIndex] = flow
        else:
            currentFlowsList.append(flow)

def getFlows(pcapFilename):
    global currentFlowsList
    global flowsList
    sniff(offline=pcapFilename,prn=addToFlowsList,store=0)
    for currentFlow in currentFlowsList:
        flowsList.append(currentFlow)

######################################################################################

###
# Then, we sort packets

def tri_rapide(flowsList):
    if not flowsList:
        return []
    else:
        pivot = flowsList[len(flowsList)//2]
        plus_petit = [flow for flow in flowsList     if flow["endTime"] < pivot["endTime"]]
        plus_grand = [flow for flow in flowsList[:-1] if flow["endTime"] >= pivot["endTime"]]
        return tri_rapide(plus_petit) + [pivot] + tri_rapide(plus_grand)



########################
# Main code
if(len(sys.argv) < 3):
    print("Commande usage : ./taps_getFlows.py <input pcap captures.pcap> <output sorted flows.json>")
    sys.exit()
capturesFilename = sys.argv[1]
sortedFlowsFilename = sys.argv[2]
if(not(os.path.isfile(capturesFilename))):
    print("ERROR: Captures file doesn't exist.")
    sys.exit()
if(os.path.isfile(sortedFlowsFilename)):
    print("ERROR: Please remove already existing sorted flows file.")
    sys.exit()

getFlows(capturesFilename)

print("All packets treated")

print("flowsList len=", len(flowsList))
print("currentFlowsList len=", len(currentFlowsList))

sortedFlowsList = tri_rapide(flowsList)

print("Flows sorted")
print("sortedFlowsList len=", len(sortedFlowsList))

for i in range(10):
    print("flow n",i,sortedFlowsList[i])
    
print("Registering sorted flows")
try:   
    os.remove(sortedFlowsFilename)
except:
    pass
f = open(sortedFlowsFilename, "w")
f.write(json.dumps(sortedFlowsList))
f.close()
print("Sorted flows registered")

algoEndTime = time.time()

print("Total time spent :", convertSecondsToPrintableTime(algoEndTime-algoStartTime))