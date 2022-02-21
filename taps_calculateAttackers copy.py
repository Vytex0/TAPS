import json

SORTED_FLOWS_FILENAME = "sortedFlows.json"
REAL_ATTACKERS_FILENAME = "realAttackers.json"

TAPS_TIMER_SECONDS = 10
TAPS_η1 = 99
TAPS_η0 = 0.01
TAPS_θ0 = 0.8
TAPS_θ1 = 0.2
TAPS_k = 3



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

    # if(ipToPort > 1 or portToIp > 1):
    #    print("ipToPort=",ipToPort)
    #    print("portToIp=",portToIp)

    deltaY[src] = deltaY.get(src, 1) # we create it if it doesnt exists
    if(ipToPort > TAPS_k or portToIp > TAPS_k):
        
        deltaY[src] = deltaY.get(src, 1) * ((1-TAPS_θ1)/(1-TAPS_θ0))
    elif(ipToPort < TAPS_k and portToIp < TAPS_k):
        deltaY[src] = deltaY.get(src, 1) * (TAPS_θ1/TAPS_θ0)


    if deltaY[src] > TAPS_η1:
        if(not(src in scan)):
            print("add",src,"to scan with delta=", deltaY[src])
            scan[src] = deltaY[src]

    if deltaY[src] < TAPS_η0:
        deltaY.pop(src)
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
            deltaY[src] = deltaY.get(src, 1) * (TAPS_θ1/TAPS_θ0)
        
    T.clear()


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

print(T)
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
    else:
        print(scanner, " was not an attacker", val)
print("-----------")
print("Summary of real attackers")
realAttackers = {k: v for k, v in sorted(realAttackers.items(), key=lambda item: item[1])}
for attacker in realAttackers:
    print(attacker, "has", realAttackers[attacker],"packets")

#print("----------")
#print("summary of deltaY")
#deltaY = {k: v for k, v in sorted(deltaY.items(), key=lambda item: item[1])}
#deltaYCount = 0
#deltaYLen = len(deltaY)
#for key in deltaY:
#    deltaYCount += 1
#    if((deltaYLen-deltaYCount) < 15):
#        break
#    print("  ",key,"->",deltaY[key])