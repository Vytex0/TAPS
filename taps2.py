from numpy import append
from scapy.all import *
import time

start_time = time.time()

TAPS_TIMER_DURATION_SECONDS = 10
TAPS_η1 = 99
TAPS_η0 = 0.01
TAPS_θ0 = 0.8
TAPS_θ1 = 0.2
TAPS_k = 3

FLOW_MAX_DURATION_SECONDS = 60

#packets = rdpcap('data/testSmall.pcap')
packets = rdpcap('data/botnet-46/capture20110815-2.truncated.pcap')
packetsLength = len(packets)

T = {} # key: src ip, value: flows
S = {} # key: src ip, value: deltaY
SCANNERS = []


def getPacketKey(packet):
    # try if packets have sport, dport, ....
    try:
        return (packet.payload.src, packet.payload.dst, packet.payload.sport, packet.payload.dport, packet.payload.proto)
    except:
        return None

currentTimerStartTime = None
for packetIndex in range(packetsLength):
    if(packetIndex%10000 == 0):
        print(packetIndex, "/", packetsLength)
    packet = packets[packetIndex]

    packetKey = getPacketKey(packet)
    if(packetKey != None): # packet is analysable
        if(currentTimerStartTime == None or (packet.time - currentTimerStartTime) > TAPS_TIMER_DURATION_SECONDS):
            print("Timer end", T)
            # We start B
            currentTimerStartTime = packet.time

            for T_src in T:
                if(not(T_src in S)):
                    S[T_src] = 1
                
                T_srcIpNb = len(T[T_src]["visitedIps"])
                T_srcPortNb = len(T[T_src]["visitedPorts"])

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
        T[srcIp]["visitedPorts"] = visitedPorts
        T[srcIp]["visitedIps"] = visitedIps

print("SOURCES", S)
print("SCANNERS", SCANNERS)

end_time = time.time()

print("Duration : ", (end_time-start_time)/60)


# source pcap reader sniff : https://stackoverflow.com/questions/10800380/scapy-and-rdpcap-function