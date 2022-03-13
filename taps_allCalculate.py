import os

botnets = ["botnet-46"]
kValues = [3, 5, 10, 30, 100, 300, 1000]
timeBins = [10, 30, 60, 120]
timers = [10, 30, 60, 120, 300, 600]

nbCalculations = len(botnets)*len(timers)*len(kValues)*len(timeBins)

print("Number of calculations to do :", nbCalculations)

roundCount = 0
for botnet in botnets:
    for timeBin in timeBins:
        for k in kValues:
            for timer in timers:
                roundCount += 1

                print("--- --- --- --- --- --- --- ---")
                print("Current botnet :", botnet)
                print("Current time bin :", timeBin)
                print("Current k value :", k)
                print("Current timer :", timer)
                print("Current stade :", roundCount, "/", nbCalculations)

                timeBin = str(timeBin)
                k = str(k)
                timer = str(timer)

                os.system("python3 taps_calculateAttackers.py data/"+botnet+"/sortedFlows-tb"+timeBin+".json data/"+botnet+"/realAttackers.json data/"+botnet+"/result-t"+timer+"-k"+k+".json data/"+botnet+"/argus-t"+timer+"-k"+k+".json")