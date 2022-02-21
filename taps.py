from numpy import append
from scapy.all import *

TAPS_TIMER_DURATION_SECONDS = 10
TAPS_η1 = 99
TAPS_η0 = 0.01
TAPS_θ0 = 0.8
TAPS_θ1 = 0.2
TAPS_k = 3

FLOW_MAX_DURATION_SECONDS = 60

packets = rdpcap('data/testSmall.pcap')

T = {} # key: src ip, value: flows
S = {} # key: src ip, value: deltaY
SCANNERS = []



######
# V1
# key : flow tuples, values: last flow packet time
#currentFlows = {}

# soucis à résoudre : si un flow termine après le timer, on a le risque que ces packets soient comptés 2 fois
#currentTimerStartTime = None

#for packet in packets:
#    try:
#        if(currentTimerStartTime == None):
#            currentTimerStartTime = packet.time
        
#        if((packet.time - currentTimerStartTime) < TAPS_TIMER_DURATION_SECONDS):
#            key = (packet.payload.src, packet.payload.dst, packet.payload.sport, packet.payload.dport, packet.payload.proto)
#            currentFlows[key] = packet.time
#        else:
#            currentTimerStartTime = None
#    except:
#        pass


#################
# V2
def getPacketKey(packet):
    # try if packets have sport, dport, ....
    try:
        return (packet.payload.src, packet.payload.dst, packet.payload.sport, packet.payload.dport, packet.payload.proto)
    except:
        return None

packetsAlreadyTreatedIndexes = [] #packets already seen during flow iterating
currentTimerStartTime = None
for packetIndex in range(len(packets)):
    if(not(packetIndex in packetsAlreadyTreatedIndexes)):
        packetsAlreadyTreatedIndexes.append(packetIndex)

        packet = packets[packetIndex]

        print("packet loop")

        packetKey = getPacketKey(packet)
        if(packetKey != None): # packet is analysable
            if(currentTimerStartTime == None or (currentTimerStartTime - packet.time) > TAPS_TIMER_DURATION_SECONDS):
                # We start B
                currentTimerStartTime = packet.time

                for T_src in T:
                    if(not(T_src in S)):
                        S[T_src] = 1
                    
                    T_srcIpNb = len(T_src["visitedIps"])
                    T_srcPortNb = len(T_src["visitedPorts"])

                    if(T_srcIpNb/T_srcPortNb < TAPS_k and T_srcPortNb/T_srcIpNb < TAPS_k):
                        S[T_src] = S[T_src]*((1-TAPS_θ1)/(1-TAPS_θ0))
                    else:
                        S[T_src] = S[T_src]*(TAPS_θ1/TAPS_θ0)

                    if(S[T_src] > TAPS_η1):
                        SCANNERS.append(T_src)
                    
                    if(S[T_src] < TAPS_η0):
                        S.pop(T_src, None)

                T.clear()

                # do smthg if T is empty

            # If we are here, it means that it is the beginning of a flow
            # Thus, we are going to iterate through the flow
            pursueFlowIterating = True
            lastFlowPacketTime = packet.time
            lastExaminedPacketIndex = packetIndex+1
            while pursueFlowIterating:
                if(not(lastExaminedPacketIndex in packetsAlreadyTreatedIndexes)):
                    lastExaminedPacket = packets[lastExaminedPacketIndex]
                    lastExaminedPacketKey = getPacketKey(lastExaminedPacket)
                    if(lastExaminedPacketKey != None):
                        if((lastExaminedPacket.time - lastFlowPacketTime) < FLOW_MAX_DURATION_SECONDS):
                            if(lastExaminedPacketKey == packetKey):
                                packetsAlreadyTreatedIndexes.append(lastExaminedPacketIndex)
                                lastFlowPacketTime = lastExaminedPacket.time
                        else:
                            pursueFlowIterating = False
                lastExaminedPacketIndex += 1
                if(lastExaminedPacketIndex >= len(packets)):
                    pursueFlowIterating = False

            # Whole flow has been seen
            srcIp = packet.payload.src
            dstIp = packet.payload.dst
            dstPort = packet.payload.dport
            T[srcIp] = T.get(srcIp, {})
            visitedPorts = T[srcIp].get("visitedPorts", [])
            visitedIps = T[srcIp].get("visitedIps", [])
            if(not(dstIp in visitedIps)):
                visitedIps.append(dstIp)
            if(not(dstPort in visitedPorts)):
                visitedPorts.append(dstPort)

print("SCANNERS", SCANNERS)