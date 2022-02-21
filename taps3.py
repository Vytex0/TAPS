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
#packets = rdpcap('data/botnet-46/capture20110815-2.truncated.pcap')
packetsLength = 4479658

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
packetIndex = 0
def packetReader(packet):
    global currentTimerStartTime
    global packetIndex
    global TAPS_TIMER_DURATION_SECONDS
    global TAPS_η1
    global TAPS_η0
    global TAPS_θ0
    global TAPS_θ1
    global TAPS_k
    global FLOW_MAX_DURATION_SECONDS
    global T
    global S
    global SCANNERS
    global packetsLength

    packetIndex += 1
    if(packetIndex%10000 == 0):
        print(packetIndex, " / ", packetsLength, "(", (packetIndex/packetsLength*100), "%")

    packetKey = getPacketKey(packet)
    if(packetKey != None): # packet is analysable
        if(currentTimerStartTime == None or (packet.time - currentTimerStartTime) > TAPS_TIMER_DURATION_SECONDS):
            #print("Timer end", T)
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
                    if(not(T_src in SCANNERS)):
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

sniff(offline="data/botnet-46/capture20110815-2.truncated.pcap",prn=packetReader,store=0)

trueScanners = []
def registerTrueScanner(packet):
    global trueScanners
    try:
        src = packet.payload.src
        if(not(src in trueScanners)):
            trueScanners.append(src)
    except:
        return None

sniff(offline="data/botnet-46/botnet-capture-20110815-fast-flux.pcap",prn=registerTrueScanner,store=0)

realFoundScanners = []
for src in trueScanners:
    if(src in SCANNERS):
        if(not(src in realFoundScanners)):
            realFoundScanners.append(src)

# ------------------


print("SOURCES", S)
print("SCANNERS", SCANNERS)

end_time = time.time()

print("Duration : ", (end_time-start_time)/60)

print("Scanners found :", len(SCANNERS))
print("True scanners nb :", len(trueScanners))
print("Real found scanners :", len(realFoundScanners))


# source pcap reader sniff : https://stackoverflow.com/questions/10800380/scapy-and-rdpcap-function