from scapy.all import *
import json
import os

#https://appdividend.com/2022/01/28/how-to-convert-python-list-to-json/

FLOW_MAX_DURATION_SECONDS = 20 # in seconds
SORTED_FLOWS_FILENAME = "sortedFlows.json"

flowsList = []
currentFlowsList = []
sortedFlowsList = []

packetsTreated = 0

def getPacketTime(packet):
    return float(packet.time)

def getPacketKey(packet):
    # try if packets have sport, dport, ....
    try:
        return (packet.payload.src, packet.payload.dst, packet.payload.sport, packet.payload.dport, packet.payload.proto)
    except:
        return None

def clearCurrentFlowsList(currentPacketTime):
    global FLOW_MAX_DURATION_SECONDS
    global flowsList
    global currentFlowsList

    flowsIndexToRemoveFromCurrent = []
    for flowIndex in range(len(currentFlowsList)):
        flow = currentFlowsList[flowIndex]
        if((currentPacketTime - flow["endTime"]) > FLOW_MAX_DURATION_SECONDS):
            flowsList.append(currentFlowsList[flowIndex])
            flowsIndexToRemoveFromCurrent.append(flowIndex)

    flowsIndexToRemoveFromCurrent.reverse()
    for index in range(len(flowsIndexToRemoveFromCurrent)):
        currentFlowsList.pop(index)

def findCurrentFlowIndex(packetKey, maxEndTime):
    global currentFlowsList

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

    flow = {}
    
    packetKey = getPacketKey(packet)
    if(packetKey != None):
        flow["key"] = packetKey
        flow["startTime"] = getPacketTime(packet)
        flow["endTime"] = getPacketTime(packet)
 
        maxEndTime = getPacketTime(packet) - FLOW_MAX_DURATION_SECONDS

        if(packetsTreated%10000 == 0):
            clearCurrentFlowsList(getPacketTime(packet))

        existingFlowIndex = findCurrentFlowIndex(packetKey, maxEndTime)

        if(existingFlowIndex != -1):
            flow["startTime"] = currentFlowsList[existingFlowIndex]["startTime"]

            currentFlowsList[existingFlowIndex] = flow
        else:
            currentFlowsList.append(flow)

def readFlows(pcapFilename):
    sniff(offline=pcapFilename,prn=addToFlowsList,store=0)


def treatPacket(packet):
    global flowsList
    global currentFlowsList
    addToFlowsList(packet)
    if(getPacketKey(packet) != None):
        if(c%1000 == 0):
            print(c,"/?")
            print("flowsList =", len(flowsList))
            print("currentFlowsList =", len(currentFlowsList))
            print("-------")

sniff(offline="data/botnet-46/capture20110815-2.truncated.pcap",prn=treatPacket,store=0)

for currentFlow in currentFlowsList:
    flowsList.append(currentFlow)

print("All packets treated")

###
# Then, we sort packets

def getMinFlowByEndTime(flowsList):
    minFlowIndex = 0
    minEndTime = flowsList[0]["endTime"]
    for flowIndex in range(len(flowsList)):
        flow = flowsList[flowIndex]
        if(flow["endTime"] < minEndTime):
            minFlowIndex = flowIndex
            minEndTime = flow["endTime"]

    return minFlowIndex

def sortFlowsList(flowsList):
    global sortedFlowsList
    for i in range(len(flowsList)):
        minFlowIndex = getMinFlowByEndTime(flowsList)
        flow = flowsList[minFlowIndex]

        sortedFlowsList.append(flowsList.pop(minFlowIndex))

print("c=", c)
print("flowsList len=", len(flowsList))
print("currentFlowsList len=", len(currentFlowsList))

sortFlowsList(flowsList)

print("Flows sorted")
print("sortedFlowsList len=", len(sortedFlowsList))

for i in range(10):
    print("flow n",i,sortedFlowsList[i])
    
print("Registering sorted flows")
os.remove(SORTED_FLOWS_FILENAME)
f = open(SORTED_FLOWS_FILENAME, "w")
f.write(json.dumps(sortedFlowsList))
f.close()
print("Sorted flows registered")