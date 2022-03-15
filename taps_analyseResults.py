import json
import sys
from os import listdir
from os.path import isfile, join

if(len(sys.argv) < 2):
    print("Commande usage : ./taps_analyseResults.py <result files directory>")
    sys.exit()

RESULT_FILES_DIRECTORY = sys.argv[1]


def displayNFirstInDictionnary(dictionnary, N):
    i = 0
    for e in dictionnary:
        if(i < N):
            print(" -", e, dictionnary[e])
        i += 1


resultFileNames = [f for f in listdir(RESULT_FILES_DIRECTORY) if (isfile(join(RESULT_FILES_DIRECTORY, f)) and f.startswith("result-"))]

successRatios = {}
falsePositiveRatios = {}

for resultFileName in resultFileNames:
    resultFile = open(join(RESULT_FILES_DIRECTORY, resultFileName), "r")
    results = json.loads(resultFile.read())
    resultFile.close()

    successRatios[resultFileName] = results["successRatio"]
    falsePositiveRatios[resultFileName] = results["falsePositiveRatio"]

bestSuccessRatios = {k: v for k, v in sorted(successRatios.items(), key=lambda item: item[1], reverse=True)}
bestFalsePositiveRatios = {k: v for k, v in sorted(falsePositiveRatios.items(), key=lambda item: item[1], reverse=True)}
worstSuccessRatios = {k: v for k, v in sorted(successRatios.items(), key=lambda item: item[1], reverse=False)}
worstFalsePositiveRatios = {k: v for k, v in sorted(falsePositiveRatios.items(), key=lambda item: item[1], reverse=False)}

print("Best successRatios:")
displayNFirstInDictionnary(bestSuccessRatios, 10)
print("--- --- --- --- --- ---")
print("Worst successRatios:")
displayNFirstInDictionnary(worstSuccessRatios, 10)
print("--- --- --- --- --- ---")
print("--- --- --- --- --- ---")
print("Best falsePositiveRatios:")
displayNFirstInDictionnary(bestFalsePositiveRatios, 10)
print("--- --- --- --- --- ---")
print("Worst falsePositiveRatios:")
displayNFirstInDictionnary(worstFalsePositiveRatios, 10)