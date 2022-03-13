import json
import matplotlib.pyplot as plt
from numpy import real
import sys
import os
import time


TAPS_TIMER_SECONDS = 150
TAPS_η1 = 99
TAPS_η0 = 0.01
TAPS_θ0 = 0.8
TAPS_θ1 = 0.2
TAPS_k = 3

########################
# Main code
if(len(sys.argv) < 7):
    print("Commande usage : ./taps_calculateAttackers.py <sorted flows file.json> <attackers list file.json> <output results.json> <output argus flows.json> <timer_seconds> <k_value>")
    sys.exit()
SORTED_FLOWS_FILENAME = sys.argv[1]
REAL_ATTACKERS_FILENAME = sys.argv[2]
OUTPUT_RESULTS_FILENAME = sys.argv[3]
OUTPUT_ARGUS_FILENAME = sys.argv[4]
ARG_TIMER = sys.argv[3]
ARG_K = sys.argv[4]
if(not(os.path.isfile(SORTED_FLOWS_FILENAME))):
    print("ERROR: Captures file doesn't exist.")
    sys.exit()
if(not(os.path.isfile(REAL_ATTACKERS_FILENAME))):
    print("ERROR: Attackers list file doesn't exist.")
    sys.exit()
if(os.path.isfile(OUTPUT_RESULTS_FILENAME)):
    print("ERROR: Please remove already existing output results file.")
    sys.exit()
if(os.path.isfile(OUTPUT_ARGUS_FILENAME)):
    print("ERROR: Please remove already existing output argus file.")
    sys.exit()


TAPS_TIMER_SECONDS = int(ARG_TIMER)
TAPS_k = int(ARG_K)


sortedFlowsFile = open(SORTED_FLOWS_FILENAME, "r")
flows = json.loads(sortedFlowsFile.read())
sortedFlowsFile.close()

realAttackersFile = open(REAL_ATTACKERS_FILENAME, "r")
realAttackers = json.loads(realAttackersFile.read())
realAttackersFile.close()



T = {}
S = []
scan = {}

deltaY = {}

argusFile = open(OUTPUT_ARGUS_FILENAME, "a")
argusFile.write("#stime,dur, runtime, proto, saddr, sport, dir, daddr, dport, state, sjit, djit, stos, dtos, pkts, bytes, trans, mean, stddev, rate, sintpkt, sintdist, sintpktact, sintdistact, sintpktidl, sintdistidl, dintpkt, dintdist, dintpktact, dintdistact, dintpktidl, dintdistidl, Taps(Normal:CC:Background), Taps(Normal:CC:Background)\n")

def generateArgusLine(epochStartTime, epochEndTime, proto, sourceAddr, sourcePort, destAddr, destPort, nbPkts, tapsResult):
    #stime	dur	 runtime	 proto	 saddr	 sport	 dir	 daddr	 dport	 state	 sjit	 djit	 stos	 dtos	 pkts	 bytes	 trans	 mean	 stddev	 rate	 sintpkt	 sintdist	 sintpktact	 sintdistact	 sintpktidl	 sintdistidl	 dintpkt	 dintdist	 dintpktact	 dintdistact	 dintpktidl	 dintdistidl	 Label(Normal:CC:Background) 	Bclus(Normal:CC:Unknown)
    stime, duration, runtime, protocol = time.strftime('%Y/%m/%d %H:%M:%S.0', time.localtime(epochStartTime)), epochEndTime-epochStartTime, epochEndTime-epochStartTime, proto
    saddr, sport, direction, daddr, dport, state = sourceAddr, sourcePort, "->", destAddr, destPort, ""
    sjit, djit, stos, dtos  = "", "", "", ""
    pkts, bytess, trans, mean = nbPkts, "", "", epochEndTime-epochStartTime
    stddev, rate, sintpkt, sintdist, sintpktact, sintdistact, sintpktidl, sintdistidl = "", "", "", "", "", "", "", ""
    dintpkt, dintdist, dintpktact, dintdistact, dintpktidl, dintdistidl = "", "", "", "", "", ""
    tapsValue = tapsResult
    return f"{stime},{duration},{runtime},{protocol},{saddr},{sport},{direction},{daddr},{dport},{state},{sjit},{djit},{stos},{dtos},{pkts},{bytess},{trans},{mean},{stddev},{rate},{sintpkt},{sintdist},{sintpktact},{sintdistact},{sintpktidl},{sintdistidl},{dintpkt},{dintdist},{dintpktact},{dintdistact},{dintpktidl},{dintdistidl},{tapsValue},{tapsValue}"

def getNbIpsBySrc(src):
    sum = 0
    #for ip in src["dstIps"]:
      #  sum += src["dstIps"][ip]
    return len(src["dstIps"])

def getNbPortsBySrc(src):
    sum = 0
    #for port in src["dstPorts"]:
    #    sum += src["dstPorts"][port]
    return len(src["dstPorts"])

def setDeltaYValue(deltaY, src, val):
    values = deltaY.get(src, [])
    values.append(val)
    deltaY[src] = values
    return deltaY

def getDeltaYValue(deltaY, src):
    values = deltaY.get(src, [1])
    return values[-1]

def updateSrcRatio(src):
    global S
    global T
    global scan
    global TAPS_k
    global TAPS_η0
    global TAPS_η1
    global TAPS_θ0
    global TAPS_θ1
    global deltaY
    if(not(src in S)):
        S.append(src)

    nbIps = getNbIpsBySrc(T[src])
    nbPorts = getNbPortsBySrc(T[src])

    ipToPort = nbIps / nbPorts
    portToIp = nbPorts / nbIps

    if(ipToPort > TAPS_k or portToIp > TAPS_k):
        deltaY = setDeltaYValue(deltaY, src, getDeltaYValue(deltaY, src) * ((1-TAPS_θ1)/(1-TAPS_θ0)))
    elif(ipToPort < TAPS_k and portToIp < TAPS_k):
        deltaY = setDeltaYValue(deltaY, src, getDeltaYValue(deltaY, src) * (TAPS_θ1/TAPS_θ0))


    if getDeltaYValue(deltaY, src) > TAPS_η1:
        if(not(src in scan)):
            print("add",src,"to scan with delta=", deltaY[src])
            scan[src] = getDeltaYValue(deltaY, src)

    if getDeltaYValue(deltaY, src) < TAPS_η0:
        deltaY = setDeltaYValue(deltaY, src, 1)
        S.remove(src)

def partB():
    global T
    global S
    global scan
    global TAPS_k
    global TAPS_η0
    global TAPS_η1
    global TAPS_θ0
    global TAPS_θ1
    global deltaY
    for src in T:
        updateSrcRatio(src)

    for src in S:
        if(not(src in T)):
            deltaY = setDeltaYValue(deltaY, src, getDeltaYValue(deltaY, src) * (TAPS_θ1/TAPS_θ0))
        
    #T.clear()


    #for src in S:
    #    updateSrcRatio(src)
    #pass
    # END OF B NOT DONE

startTimerTime = flows[0]["startTime"]
for flow in flows:
    if(flow["startTime"] < startTimerTime):
        startTimerTime = flow["startTime"]

timerCount = 0
flowCount = 0
totalFlowNb = len(flows)
for flow in flows:
    flowCount+= 1
    if((flow["endTime"]-startTimerTime) > TAPS_TIMER_SECONDS):
        print("part B")
        partB()
        timerCount += 1
        startTimerTime = flow["endTime"]
    
    (src, dst, srcPort, dstPort, proto) = flow["key"]

    T[src] = T.get(src, {"dstIps": [], "dstPorts": []})

    dstIps = T[src]["dstIps"]
    dstPorts = T[src]["dstPorts"]

    if(not(dst in dstIps)):
        dstIps.append(dst)
    if(not(dstPort in dstPorts)):
        dstPorts.append(dstPort)

    T[src]["dstIps"] = dstIps
    T[src]["dstPorts"] = dstPorts

    if(flowCount %1000 == 0):
        print(flowCount, "/", totalFlowNb)

    # register to argus file
    tapsResult = "Unknown"
    if(src in scan):
        tapsResult = "From-Botnet"
    elif(not(src in S)):
        tapsResult = "Normal"
    argusFile.write(generateArgusLine(flow["startTime"], flow["endTime"], proto, src, srcPort, dst, dstPort, 1, tapsResult)+"\n")

    if(totalFlowNb == flowCount):
        print("final part B")
        partB()
        timerCount += 1
        startTimerTime = flow["endTime"]





nbTrueScannersDetected = 0
nbTrueScanners = 0
nbFalseScannersDetected = 0
nbTrueScannersMissed = 0

print("len flows=", len(flows))
print("len scan=", len(scan))
print("timerCount =", timerCount)
print("-----------")
print("Summary of attackers")
#print(realAttackers)
for scanner in scan:
    val = scan[scanner]
    if(scanner in realAttackers):
        print(scanner, " is a real attacker", val, "-----")
        nbTrueScannersDetected += 1
    else:
        print(scanner, " was not an attacker", val)
        nbFalseScannersDetected += 1
print("-----------")
print("Summary of real attackers")
realAttackers = {k: v for k, v in sorted(realAttackers.items(), key=lambda item: item[1])}
nbRealAttackers = 0
for attacker in realAttackers:
    if(attacker in deltaY):
        nbTrueScanners += 1
        if(not(attacker in scan)):
            nbTrueScannersMissed += 1
        nbRealAttackers +=1
        print(attacker, "has", realAttackers[attacker],"packets")
        #plt.plot(deltaY[attacker], label=attacker)
        #plt.show()
print("nbRealAttackers =",nbRealAttackers)

print("----------")
print("summary of deltaY")
deltaY = {k: v for k, v in sorted(deltaY.items(), key=lambda item: item[1])}
deltaYCount = 0
deltaYLen = len(deltaY)
for key in deltaY:
    deltaYCount += 1
    if((deltaYLen-deltaYCount) < 40):
        if(key in realAttackers):
            print("  ",key,"->",deltaY[key][-1], "attaquant -----")
        else:
            print("  ",key,"->",deltaY[key][-1], "non attaquant")

print("----------")
print("test statistics")
print("  Success ratio =", (nbTrueScannersDetected/nbTrueScanners))
print("  False positive ratio =", (nbFalseScannersDetected/nbTrueScanners))
print("  False negative ratio =", (nbTrueScannersMissed/nbTrueScanners))

print("----------")
print("registering results :")
results = {}
results["lenFlows"] = len(flows)
results["lenScan"] = len(scan)
results["lenDeltaY"] = len(deltaY)
results["timerCount"] = timerCount
results["nbRealAttackers"] = nbRealAttackers
results["nbTrueScanners"] = (nbTrueScanners)
results["nbTrueScannersDetected"] = (nbTrueScannersDetected)
results["nbFalseScannersDetected"] = (nbFalseScannersDetected)
results["nbTrueScannersMissed"] = (nbTrueScannersMissed)
results["successRatio"] = (nbTrueScannersDetected/nbTrueScanners)
results["falsePositiveRatio"] = (nbFalseScannersDetected/nbTrueScanners)
results["falseNegativeRatio"] = (nbTrueScannersMissed/nbTrueScanners)
try:   
    os.remove(OUTPUT_RESULTS_FILENAME)
except:
    pass
f = open(OUTPUT_RESULTS_FILENAME, "w")
f.write(json.dumps(results))
f.close()
print("Results registered")

argusFile.close()